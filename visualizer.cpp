/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2014-2019,  Regents of the University of California,
 *                           Arizona Board of Regents,
 *                           Colorado State University,
 *                           University Pierre & Marie Curie, Sorbonne University,
 *                           Washington University in St. Louis,
 *                           Beijing Institute of Technology,
 *                           The University of Memphis.
 *
 * This file is part of NFD (Named Data Networking Forwarding Daemon).
 * See AUTHORS.md for complete list of NFD authors and contributors.
 *
 * NFD is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 *
 * NFD is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * NFD, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "nfd.hpp"
#include "rib/service.hpp"

#include "common/global.hpp"
#include "common/logger.hpp"
#include "common/privilege-helper.hpp"
#include "core/version.hpp"

#include <string.h> // for strsignal()

#include <boost/config.hpp>
#include <boost/exception/diagnostic_information.hpp>
#include <boost/filesystem.hpp>
#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/version.hpp>

#include <atomic>
#include <condition_variable>
#include <iostream>
#include <thread>
#include <ndn-cxx/util/logging.hpp>
#include <ndn-cxx/version.hpp>
#include <ndn-cxx/transport/unix-transport.hpp>
#include "face/unix-stream-transport.hpp"
#include <ndn-cxx/mutator.hpp>
#include "../../Fuzzer/FuzzerDefs.h"
#include "face/pcap-helper.hpp"

#ifdef HAVE_LIBPCAP
#include <pcap/pcap.h>
#endif
#ifdef HAVE_SYSTEMD
#include <systemd/sd-daemon.h>
#endif
#ifdef HAVE_WEBSOCKET
#include <websocketpp/version.hpp>
#endif

namespace po = boost::program_options;

NFD_LOG_INIT(Main);

namespace nfd {

/** \brief Executes NFD with RIB manager
 *
 *  NFD (main forwarding procedure) and RIB manager execute in two different threads.
 *  Each thread has its own instances of global io_service and global scheduler.
 *
 *  When either of the daemons fails, execution of non-failed daemon will be terminated as
 *  well.  In other words, when NFD fails, RIB manager will be terminated; when RIB manager
 *  fails, NFD will be terminated.
 */
class NfdRunner : noncopyable
{
public:
  explicit
  NfdRunner(const std::string& configFile)
    : m_nfd(configFile, m_nfdKeyChain)
    , m_configFile(configFile)
    , m_terminationSignalSet(getGlobalIoService())
    , m_reloadSignalSet(getGlobalIoService())
  {
    m_terminationSignalSet.add(SIGINT);
    m_terminationSignalSet.add(SIGTERM);
    m_terminationSignalSet.async_wait(bind(&NfdRunner::terminate, this, _1, _2));

    m_reloadSignalSet.add(SIGHUP);
    m_reloadSignalSet.async_wait(bind(&NfdRunner::reload, this, _1, _2));
  }

  void
  initialize()
  {
    m_nfd.initialize();
  }

  int
  run()
  {
    // Return value: a non-zero value is assigned when either NFD or RIB manager (running in
    // a separate thread) fails.
    std::atomic_int retval(0);

    boost::asio::io_service* const mainIo = &getGlobalIoService();
    setMainIoService(mainIo);
    boost::asio::io_service* ribIo = nullptr;

    // Mutex and conditional variable to implement synchronization between main and RIB manager
    // threads:
    // - to block main thread until RIB manager thread starts and initializes ribIo (to allow
    //   stopping it later)
    std::mutex m;
    std::condition_variable cv;

    std::thread ribThread([configFile = m_configFile, &retval, &ribIo, mainIo, &cv, &m] {
      {
        std::lock_guard<std::mutex> lock(m);
        ribIo = &getGlobalIoService();
        BOOST_ASSERT(ribIo != mainIo);
        setRibIoService(ribIo);
      }
      cv.notify_all(); // notify that ribIo has been assigned

      try {
        ndn::KeyChain ribKeyChain;
        // must be created inside a separate thread
        rib::Service ribService(configFile, ribKeyChain);
        getGlobalIoService().run(); // ribIo is not thread-safe to use here
      }
      catch (const std::exception& e) {
        NFD_LOG_FATAL(boost::diagnostic_information(e));
        retval = 1;
        mainIo->stop();
      }

      {
        std::lock_guard<std::mutex> lock(m);
        ribIo = nullptr;
      }
    });

    {
      // Wait to guarantee that ribIo is properly initialized, so it can be used to terminate
      // RIB manager thread.
      std::unique_lock<std::mutex> lock(m);
      cv.wait(lock, [&ribIo] { return ribIo != nullptr; });
    }

    try {
      systemdNotify("READY=1");
      mainIo->run();
    }
    catch (const std::exception& e) {
      NFD_LOG_FATAL(boost::diagnostic_information(e));
      retval = 1;
    }
    catch (const PrivilegeHelper::Error& e) {
      NFD_LOG_FATAL(e.what());
      retval = 4;
    }

    {
  // ribIo is guaranteed to be alive at this point
      std::lock_guard<std::mutex> lock(m);
      if (ribIo != nullptr) {
        ribIo->stop();
        ribIo = nullptr;
      }
    }
    ribThread.join();

    return retval;
  }

  static void
  systemdNotify(const char* state)
  {
#ifdef HAVE_SYSTEMD
    sd_notify(0, state);
#endif
  }

private:
  void
  terminate(const boost::system::error_code& error, int signalNo)
  {
    if (error)
      return;

    NFD_LOG_INFO("Caught signal " << signalNo << " (" << ::strsignal(signalNo) << "), exiting...");

    systemdNotify("STOPPING=1");
    getGlobalIoService().stop();
  }

  void
  reload(const boost::system::error_code& error, int signalNo)
  {
    if (error)
      return;

    NFD_LOG_INFO("Caught signal " << signalNo << " (" << ::strsignal(signalNo) << "), reloading...");

    systemdNotify("RELOADING=1");
    m_nfd.reloadConfigFile();
    systemdNotify("READY=1");

    m_reloadSignalSet.async_wait(bind(&NfdRunner::reload, this, _1, _2));
  }

private:
  ndn::KeyChain           m_nfdKeyChain;
  Nfd                     m_nfd;
  std::string             m_configFile;

  boost::asio::signal_set m_terminationSignalSet;
  boost::asio::signal_set m_reloadSignalSet;
};

/*static void
printUsage(std::ostream& os, const char* programName, const po::options_description& opts)
{
  os << "Usage: " << programName << " [options]\n"
     << "\n"
     << "Run the NDN Forwarding Daemon (NFD)\n"
     << "\n"
     << opts;
}

static void
printLogModules(std::ostream& os)
{
  const auto& modules = ndn::util::Logging::getLoggerNames();
  std::copy(modules.begin(), modules.end(), ndn::make_ostream_joiner(os, "\n"));
  os << std::endl;
}*/

} // namespace nfd




boost::asio::io_service m_ioService;
boost::asio::local::stream_protocol::endpoint ep;
boost::asio::local::stream_protocol::socket sock(m_ioService);
boost::asio::io_service m_ioService1;
boost::asio::local::stream_protocol::socket sock1(m_ioService1);
boost::asio::io_service m_ioService2;
boost::asio::local::stream_protocol::socket sock2(m_ioService2);


/*int 
LLVMFuzzerTestOneInput1(const uint8_t *Data, size_t Size) 
{
 using namespace nfd;
 if(Size <= 2 )return 0;
boost::asio::local::stream_protocol::socket* s;
 int socky = Data[0];
 Data++;
 Size--;
 if(Size <= 2 )return 0;
    ndn::Block wire(Data, Size);
    wire.parse();


if(socky==0){
std::cout<<"sock\n";
 s = &sock;
}
else if(socky==1){
std::cout<<"sock1\n";
 s = &sock1;
}
else {
std::cout<<"sock2\n";
 s = &sock2;
}
 s->send(boost::asio::buffer(wire.wire(), wire.size()));


  return 0;//runner.run();
}
*/
int
main(int argc, char** argv){
  using namespace nfd;
  std::string configFile = DEFAULT_CONFIG_FILE;
  std::thread NFDThread([configFile]{//, &wire] {
  NfdRunner runner(configFile);
  runner.initialize();
  return runner.run();
  });



  ep = boost::asio::local::stream_protocol::endpoint("/run/nfd.sock");
  usleep(500000);
  sock.connect(ep);
  sock1.connect(ep);
  sock2.connect(ep);
  ndn::nfd::CommandOptions options;
  ndn::security::SigningInfo signingInfo;
  options.setSigningInfo(signingInfo);
  ControlParameters parameters = ndn::nfd::ControlParameters().setName("/a").setFlags(0);
  shared_ptr<ControlCommand> command = make_shared<ndn::nfd::RibRegisterCommand>();
  //std::cout<<options.getPrefix()<<std::endl;
  Name requestName = command->getRequestName(options.getPrefix(), parameters);
  ndn::KeyChain keyChain;
  ndn::security::CommandInterestSigner m_signer(keyChain);
  Interest interest = m_signer.makeCommandInterest(requestName, options.getSigningInfo());
  interest.setInterestLifetime(options.getTimeout());
  ndn::Block wire = interest.wireEncode();
  sock.send(boost::asio::buffer(wire.wire(), wire.size()));


  ControlParameters parameters1 = ndn::nfd::ControlParameters().setName("/b").setFlags(0);
  shared_ptr<ControlCommand> command1 = make_shared<ndn::nfd::RibRegisterCommand>();
  //std::cout<<options.getPrefix()<<std::endl;
  Name requestName1 = command1->getRequestName(options.getPrefix(), parameters1);
  ndn::KeyChain keyChain1;
  ndn::security::CommandInterestSigner m_signer1(keyChain1);
  Interest interest1 = m_signer1.makeCommandInterest(requestName1, options.getSigningInfo());
  interest1.setInterestLifetime(options.getTimeout());
  ndn::Block wire1 = interest1.wireEncode();
  sock1.send(boost::asio::buffer(wire1.wire(), wire1.size()));


  ControlParameters parameters2 = ndn::nfd::ControlParameters().setName("/c").setFlags(0);
  shared_ptr<ControlCommand> command2 = make_shared<ndn::nfd::RibRegisterCommand>();
  //std::cout<<options.getPrefix()<<std::endl;
  Name requestName2 = command2->getRequestName(options.getPrefix(), parameters2);
  ndn::KeyChain keyChain2;
  ndn::security::CommandInterestSigner m_signer2(keyChain2);
  Interest interest2 = m_signer2.makeCommandInterest(requestName2, options.getSigningInfo());
  interest2.setInterestLifetime(options.getTimeout());
  ndn::Block wire2 = interest2.wireEncode();
  sock2.send(boost::asio::buffer(wire2.wire(), wire2.size()));
  //boost::asio::local::stream_protocol::endpoint lep = sock.local_endpoint();
  //face::PcapHelper(ep.path());
  std::ifstream File(argv[1]);
//  std::ifstream File("packetTrace.csv");
  std::string packetType, compare;
  std::string bytes;
//int he = 0;  
  uint8_t* byt = ( uint8_t*) malloc(sizeof(uint8_t)*4096);
  boost::asio::local::stream_protocol::socket* s;
  getline(File, packetType);
  while(getline(File, packetType, ',')) {
    //std::cout << "ID: " << he++ << "\n" ; 
  
    std::string socket; 
    getline(File, socket, ',');
    if(socket=="0"){
      //std::cout<<"sock\n";
       s = &sock;
    }
    else if(socket=="1"){
    //std::cout<<"sock1\n";
       s = &sock1;
    }
    else {
       //std::cout<<"sock2\n";
       s = &sock2;
    }


    getline(File,bytes);
    int k =0;
//if (he == 45) continue;
    for(size_t i=0; i < bytes.size(); i++){
       uint8_t temp = 0;
       if(bytes[i]-'0' > 9)
           temp += (bytes[i]-'a'+10)*16;
       else 
           temp += (bytes[i]-'0')*16;
       i++;
       if(bytes[i]-'0' > 9)
           temp += (bytes[i]-'a'+10);
       else
           temp += (bytes[i]-'0');
       byt[k] = temp;
//  printf("%02x", temp);
       k++; 
  }
//printf("\n%d\n", k);
// std::cout << "User:\n" << bytes << "\n" ;

    s->send(boost::asio::buffer(byt,k));  
   usleep(1000);
//    LLVMFuzzerTestOneInput1();
  }
  free(byt);

  std::cout<<"done\n";
  getMainIoService().stop();
  NFDThread.join();
  return 0;
}

