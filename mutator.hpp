/*
  * Copyright (c) 2013-2018 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 *  terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
  * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 *
 * @author Alexander Afanasyev <http://lasr.cs.ucla.edu/afanasyev/index.html>
 */
#ifndef MUTATOR_HPP
#define MUTATOR_HPP
#include <ndn-cxx/face.hpp>
#include "ndn-cxx/encoding/buffer-stream.hpp"
#include "ndn-cxx/security/transform/digest-filter.hpp"
#include "ndn-cxx/security/transform/step-source.hpp"
#include "ndn-cxx/security/transform/stream-sink.hpp"
#include <iostream>
// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
#include <stdint.h>
#include <stddef.h>
//#include "ndn-cxx/Mutator.hpp"


namespace ndn {
// Additional nested namespaces can be used to prevent/limit name conflicts

#ifdef CUSTOM_MUTATOR
//#include "ndn-cxx/Mutator.hpp"
size_t deleteComponent(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t copyCurrentCompnents(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t suffleComponents(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t addrandomTLVComponent(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
extern uint32_t randomlyChooseField(Block m_wire,unsigned int Seed, int ensureSatisfaction);
size_t mutateNonsubTLVfield(Block wire, uint32_t field, unsigned int Seed, uint8_t* dat, size_t Size, size_t MaxSize);
size_t mutateSelectors(Block wire, unsigned int Seed, uint8_t* dat, size_t Size, size_t MaxSize);
size_t mutateForwardingHint(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t deleteFHDel(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t addFHDel(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t suffleFHDel(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t changeFHDelTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateName(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t deleteNameCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t addNameCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t suffleNameCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t changeNameComTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateSignatureInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t deleteSigInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t addSigInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t suffleSigInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t changeSigInfoTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateKeyLocator(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateMetaInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize, int ensureSatisfaction);
size_t deleteMeta(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t addMeta(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t suffleMeta(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t changeMetaTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateFinalBlockId(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t mutateAppParam(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t deleteAppParam(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t addAppParam(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t suffleAppParam(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t changeAppParamTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
size_t computeDigest(Block wire, Block subwire, uint32_t field, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize);
enum : uint32_t {deletion = 0, addition = 1, suffle = 2, TLVchange = 3, fieldmutation = 4};
Block createField(Block wire, uint32_t field);

extern "C" size_t
LLVMFuzzerMutate(uint8_t *Dat, size_t Size, size_t MaxSize);

size_t LLVMFuzzerCustomMutator1(Block wire, uint8_t *Dat, size_t Size,
                                          size_t MaxSize, unsigned int Seed) {
  srand (Seed);
  uint32_t mutationType = (rand()%5);
  mutationType = fieldmutation;
  if(mutationType != fieldmutation){
     switch(mutationType){
        case deletion :
           return deleteComponent(wire, Seed, Dat, Size, MaxSize);
           break;
        case addition :
           return copyCurrentCompnents(wire, Seed, Dat, Size, MaxSize);
           break;
        case suffle :
           return suffleComponents(wire, Seed, Dat, Size, MaxSize);
           break;
        case TLVchange :
           return addrandomTLVComponent(wire, Seed, Dat, Size, MaxSize);
           break;
     }
     return 0;
  }
  int ensureSatisfaction = rand()%100;
  uint32_t field = randomlyChooseField(wire, Seed, ensureSatisfaction);
  wire.parse();
  Block::element_const_iterator element = wire.find(field);

  if (element == wire.elements_end()){
      wire = createField(wire, field);
      wire.parse();
      element = wire.find(field);
  }
  Block subwire = *element;

  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*4096);
  size_t i;
  size_t len;
  const uint8_t* loopwire = element->value();
  for(i = 0; i < element->value_size(); i++){
     bytes1[i] = loopwire[i];
     }

  if (field ==  tlv::Name){
     len = mutateName(subwire, Seed, bytes1,Size, MaxSize);
}
  else if(field == tlv::Selectors){
     len = mutateSelectors(subwire, Seed, bytes1, Size, MaxSize);
  }
  else if(field == tlv::ForwardingHint){
     len = mutateForwardingHint(subwire, Seed, bytes1,Size, MaxSize);
  }
  else if(field == tlv::SignatureInfo){
     len = mutateSignatureInfo(subwire, Seed, bytes1,Size, MaxSize);
  }
  else if(field == tlv::MetaInfo){
     len = mutateMetaInfo(subwire, Seed, bytes1,Size, MaxSize, ensureSatisfaction);
  }
  else if(field == tlv::ApplicationParameters){
     len = mutateAppParam(subwire, Seed, bytes1,Size, MaxSize);
  }
  else{
     len = mutateNonsubTLVfield(wire, field, Seed, bytes1, Size, MaxSize);
  }
  element = wire.elements_end();
  size_t totalLength = 0;
  element--;
  EncodingEstimator estimator;
  size_t estimatedSize;
  if (wire.type() == tlv::Interest){
     Interest interest;
     interest.setCanBePrefix(false);
     estimatedSize = interest.wireEncode(estimator);
  }
  else{
     Data data;
     KeyChain keyChain;
     keyChain.sign(data);
     estimatedSize = data.wireEncode(estimator); 
  }
  EncodingBuffer encoder(estimatedSize, 0);

  for(size_t i=0;i<wire.elements_size();i++){
     if(field == wire.elements()[i].type()){
        if(len == 0 )continue;
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  bytes1, len);
     }
     else if(field == tlv::ApplicationParameters && wire.elements()[i].type() == tlv::Name){
         EncodingBuffer tempEncoder(estimatedSize, 0);
         size_t Length = tempEncoder.prependByteArray(bytes1, len);
         Length += tempEncoder.prependVarNumber(len);
         Length += tempEncoder.prependVarNumber(tlv::ApplicationParameters);
         uint8_t* bytes2 = ( uint8_t*) malloc(sizeof(uint8_t)*4096);
         size_t namelen = computeDigest(wire.elements()[i], tempEncoder.block(), field, Seed, bytes2, Size, MaxSize);

         totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), bytes2 , namelen);
         free(bytes2);

     }
     else
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(wire.type());
  const uint8_t* bytes2 = encoder.block().wire();
  if(encoder.block().size()>MaxSize) return Size;

  for(size_t j = 0; j < encoder.block().size(); j++){
     Dat[j] = bytes2[j];
  }

   free(bytes1);
   return encoder.block().size();
}

size_t deleteComponent(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if(wire.elements_size() < 2)return wire.size();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Interest interest;
  wire.parse();
  size_t estimatedSize = interest.wireEncode(estimator);
  uint32_t position = 1+(rand()%(wire.elements_size()-2));
  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
  bytes[0] = 255;

  size_t i;

  for(i=0;i<wire.elements_size();i++){
        if(i==position) continue;
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Interest);
  size_t len = encoder.block().size();
  const uint8_t* loopwire = encoder.block().wire();
  for(i = 0; i < len; i++){
     Dat[i]= loopwire[i];
     }
  free(bytes); 
  return len;
}


size_t computeDigest(Block wire, Block subwire, uint32_t field, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  //if (wire.elements_size() == 0 ) return wire.value_size();
  wire.parse();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  size_t estimatedSize = name.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  for(size_t i=0;i<wire.elements_size();i++){
     if(field == tlv::ApplicationParameters && wire.elements()[i].type() == tlv::ParametersSha256DigestComponent){
         if(subwire.value_size() == 0 )continue;
         using namespace security::transform;
         StepSource in;
         OBufferStream out;
         in >> digestFilter(DigestAlgorithm::SHA256) >> streamSink(out);
         subwire.parse();
  //       std::for_each(subwire.elements_begin(), subwire.elements_end(), [&] (const Block& b) {
  //          in.write(b.wire(), b.size());
    //     });
            in.write(subwire.wire(), subwire.size());
         in.end();
          out.buf();
         //Block temp(out.buf());
         auto digestComponent = name::Component::fromParametersSha256Digest(out.buf());
         Block wi = digestComponent.wireEncode();
         totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  wi.value(), wi.value_size());
     }
     else
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Name);
  size_t len = encoder.block().value_size();
  const uint8_t* loopwire = encoder.block().value();
  for(size_t i = 0; i < len; i++){
     Dat[i]= loopwire[i];
  }

  return len;
}

size_t addrandomTLVComponent(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if((MaxSize-5) <= (Size))return wire.value_size();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  wire.parse();
  size_t estimatedSize = name.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
  bytes[0] = 255;

  uint32_t newTLV = (rand()%(std::numeric_limits<uint32_t>::max()));
  for(size_t i=0;i<wire.elements_size();i++){
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  totalLength += encoder.appendByteArrayBlock(newTLV,  bytes, 1);
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Interest);
  size_t len = encoder.block().size();
  const uint8_t* loopwire = encoder.block().wire();
  for(size_t i = 0; i < len; i++){
     Dat[i]= loopwire[i];
  }

  free(bytes);
  return len;
}

size_t copyCurrentCompnents(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if(MaxSize <= Size*2)return wire.size();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Interest interest;
  wire.parse();
  size_t estimatedSize = interest.wireEncode(estimator);
  EncodingBuffer encoder(estimatedSize, 0);

  size_t i;

  for(i=0;i<wire.elements_size();i++){
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  for(i=0;i<wire.elements_size();i++){
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Interest);
  size_t len = encoder.block().size();
  const uint8_t* loopwire = encoder.block().wire();
  for(i = 0; i < len; i++){
     Dat[i]= loopwire[i];
     }

  return len;
}

size_t suffleComponents(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
return 0;
}

uint32_t randomlyChooseField(Block m_wire, unsigned int Seed, int ensureSatisfaction){
  int ele;
  if(m_wire.type() == tlv::Data){
     if(ensureSatisfaction > 10)
        ele = (rand()%5);
     else 
        ele = 1+(rand()%4);
     uint32_t array [5]= {7,20,21,22,23};
     return array[ele];}
  ele = (rand()%5);
  uint32_t array [8]= {7,30,10,12,34,36};
  return array[ele];
}

uint32_t randomlyChooseSubField(Block m_wire, unsigned int Seed){
  int ele;
  m_wire.parse();
  uint32_t selectorFields [6]= {tlv::MinSuffixComponents, tlv::MaxSuffixComponents, tlv::ChildSelector, tlv::MustBeFresh} ;
  uint32_t sigInfoFields [7]= {tlv::SignatureType, tlv::KeyLocator, tlv::AdditionalDescription, tlv::DescriptionEntry, tlv::DescriptionKey, tlv::DescriptionValue, tlv::ValidityPeriod} ;
 uint32_t metaInfoFields [3]={tlv::ContentType, tlv::FreshnessPeriod, tlv::FinalBlockId};
  if(m_wire.type() == tlv::Selectors){
     ele = (rand()%4);
     return selectorFields[ele];}
  else if(m_wire.type() == tlv::SignatureInfo){
     ele = (rand()%6);
     return sigInfoFields[ele];  
  }
  else if(m_wire.type() == tlv::MetaInfo){
     ele = (rand()%3);
     return metaInfoFields[ele];
  }
  else{
     if(m_wire.elements_size()<=1) return 0;
     else {
        ele = (rand()%m_wire.elements_size());
        return ele;
     }
  }
}

size_t mutateNonsubTLVfield(Block wire, uint32_t field, unsigned int Seed, uint8_t* dat, size_t Size, size_t MaxSize){
  wire.parse();
  Block::element_const_iterator element = wire.find(field);
  if (field == tlv::ContentType)field = tlv::SignatureType;
  if (field == tlv::FreshnessPeriod || field == tlv::LinkPreference)field = tlv::InterestLifetime;
  size_t len;
  do {
        if (field == tlv::InterestLifetime || field == tlv::SignatureType || field == tlv::Nonce)len = LLVMFuzzerMutate(dat,element->value_size(),8);
        else if(field == tlv::HopLimit) len = LLVMFuzzerMutate(dat,element->value_size(),1); 
        else{
           size_t freespace = MaxSize-Size-8;
         if(MaxSize <= Size+8)
              freespace = 0;
           len = LLVMFuzzerMutate(dat,element->value_size(),freespace+element->value_size());
      }
  }while((field == tlv::SignatureType  && len != 1 && len != 2)||(field == tlv::InterestLifetime && len != 1 && len != 2  && len != 4  && len != 8 )|| (field == tlv::Nonce && len != 4));
   return len;
}

size_t mutateSelectors(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
return wire.value_size();//Handle this

  uint32_t field = randomlyChooseSubField(wire, Seed);
  size_t len;
  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*4096);
  size_t i;
  wire.parse();
  Block::element_const_iterator element = wire.find(field);
  if (element == wire.elements_end()){
     wire = createField(wire, field);
     wire.parse();
     element = wire.find(field);
  }
  const uint8_t* byteTransfer = element->value();
  for(i = 0; i < element->value_size(); i++){
     bytes1[i] = byteTransfer[i];
  }
  if (field ==  tlv::Exclude){
     return 0;
  }
  else if(field == tlv::KeyLocator){
     return 0;
  }
  else{
     len = mutateNonsubTLVfield(wire, field, Seed, bytes1, Size, MaxSize);
}  size_t totalLength = 0;

  EncodingEstimator estimator;
  Selectors selector;
  size_t estimatedSize = selector.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  Block::element_const_iterator val = wire.find(tlv::MustBeFresh);
  if (val != wire.elements_end()){
     if(field == tlv::MustBeFresh)
        totalLength += encoder.prependByteArrayBlock(tlv::MustBeFresh,  bytes1, len);
     else
        totalLength += encoder.prependByteArrayBlock(tlv::MustBeFresh,  val->value(), val->value_size());
  }
  val = wire.find(tlv::ChildSelector);
  if (val != wire.elements_end()){
     if(field == tlv::ChildSelector)
        totalLength += encoder.prependByteArrayBlock(tlv::ChildSelector,  bytes1, len);
     else
        totalLength += encoder.prependByteArrayBlock(tlv::ChildSelector,  val->value(), val->value_size());
  }
  val = wire.find(tlv::Exclude);
  if (val != wire.elements_end()){
     if(field == tlv::Exclude)
        totalLength += encoder.prependByteArrayBlock(tlv::Exclude,  bytes1, len);
     else
        totalLength += encoder.prependByteArrayBlock(tlv::Exclude,  val->value(), val->value_size());
  }
  val = wire.find(tlv::KeyLocator);
  if (val != wire.elements_end()){
     if(field == tlv::KeyLocator)
        totalLength += encoder.prependByteArrayBlock(tlv::KeyLocator,  bytes1, len);
     else
        totalLength += encoder.prependByteArrayBlock(tlv::KeyLocator,  val->value(), val->value_size());
  }
  val = wire.find(tlv::MaxSuffixComponents);
  if (val != wire.elements_end()){
     if(field == tlv::MaxSuffixComponents)
        totalLength += encoder.prependByteArrayBlock(tlv::MaxSuffixComponents,  bytes1, len);
     else
        totalLength += encoder.prependByteArrayBlock(tlv::MaxSuffixComponents,  val->value(), val->value_size());
  }
 val = wire.find(tlv::MinSuffixComponents);
 if (val != wire.elements_end()){
     if(field == tlv::MinSuffixComponents)
        totalLength += encoder.prependByteArrayBlock(tlv::MinSuffixComponents,  bytes1, len);
     else
        totalLength += encoder.prependByteArrayBlock(tlv::MinSuffixComponents,  val->value(), val->value_size());
  }
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Selectors); 

  const uint8_t* bytes2 = encoder.block().wire();
  for(size_t j = 0; j < encoder.block().size(); j++){
     Dat[j] = bytes2[j];
  }
 free(bytes1);
 return totalLength;
}

Block createField(Block wire, uint32_t field ){
  if(wire.type()==tlv::Interest){
     Interest interest;
     interest.wireDecode(wire);
     DelegationList del;
     Name hname("test");
     switch(field) {
      case tlv::Selectors :
        interest.setMustBeFresh(true);
	break;
      case tlv::Nonce :
        interest.setNonce(0);
        break;
      case tlv::InterestLifetime : 
	interest.setInterestLifetime(2_s);
	break;
      case tlv::ForwardingHint :
        del.insert(64, hname, DelegationList::INS_APPEND);
        interest.setForwardingHint(del);
        break;
      case tlv::HopLimit :
         interest.setHopLimit(0);
         break;
      case tlv::ApplicationParameters :
         const uint8_t bytes[3]={128, 1,255};
         interest.setApplicationParameters(bytes, 3);
         break;
     }
     return interest.wireEncode();
  }
  else if(wire.type()==tlv::Data){
     Data data;
     data.wireDecode(wire);
     const uint8_t bytes[1]={255};
     switch(field) {
      case tlv::MetaInfo :
        data.setMetaInfo(MetaInfo());
        break;
      case tlv::Content :
        data.setContent(bytes, 1);
        break;
      case tlv::SignatureInfo : case tlv::SignatureValue :
        data.setSignature(Signature());
        break;
     }
     return data.wireEncode();
  }
  else if(wire.type()==tlv::SignatureInfo){
     SignatureInfo sig; 
     sig.wireDecode(wire);
     if (field == tlv::KeyLocator){
        KeyLocator kl("T");
        sig.setKeyLocator(kl);
     }
     else if(field == tlv::ValidityPeriod){
        const time::system_clock::TimePoint notb = time::fromIsoString("1400.10");
        const time::system_clock::TimePoint nota = time::fromIsoString("1400.10");
        security::ValidityPeriod vp(notb, nota);
        sig.setValidityPeriod(vp);
     }
     else {
        uint8_t byte[3]={static_cast<uint8_t>(field), 1, 255};
        Block block(byte,3);        
        sig.appendTypeSpecificTlv(block);
     }
     return sig.wireEncode();
  }
  else if(wire.type()==tlv::MetaInfo){
     MetaInfo mInfo;
     mInfo.wireDecode(wire);
     if(field == tlv::ContentType){
        mInfo.setType(1);  
     }
     else if(field == tlv::FreshnessPeriod){
        mInfo.setFreshnessPeriod(2_s);
     }
     else{
        mInfo.setFinalBlock(name::Component("A"));
     }
     return mInfo.wireEncode(); 
  }
  else{
     Selectors selector;
     selector.wireDecode(wire);
     switch(field) {
      case tlv::MinSuffixComponents :
        selector.setMinSuffixComponents(1);
        selector.getMinSuffixComponents();
        break;
      case tlv::MaxSuffixComponents :
        selector.setMaxSuffixComponents(0);
        selector.getMaxSuffixComponents();
        break;
      case tlv::KeyLocator :
        break;
      case tlv::Exclude :
        break;
      case tlv::ChildSelector :
        selector.setChildSelector(1);
        selector.getChildSelector();
        break;
      case tlv::MustBeFresh :
        selector.setMustBeFresh(1);
        selector.getMustBeFresh();
        break;
     }
     return selector.wireEncode();
  }
}

size_t mutateForwardingHint(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  uint32_t mutationType = (rand()%5);
  if(mutationType != fieldmutation){
     switch(mutationType){
        case deletion :
           return deleteFHDel(wire, Seed, Dat, Size, MaxSize);
           break;
        case addition :
           return addFHDel(wire, Seed, Dat, Size, MaxSize);
           break;
        case suffle :
           return suffleFHDel(wire, Seed, Dat, Size, MaxSize);
           break;
        case TLVchange :
           return changeFHDelTLV(wire, Seed, Dat, Size, MaxSize);
           break;
     }
     return 0;
  }
  uint32_t field = randomlyChooseSubField(wire, Seed);
size_t len;
  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*4096);
  size_t i;
  wire.parse();
  Block subwire = wire.elements()[field];
  int ele = (rand()%2);
  subwire.elements()[ele];
  const uint8_t* byteTransfer = subwire.elements()[ele].value();
  for(i = 0; i < subwire.elements()[ele].value_size(); i++){
     bytes1[i] = byteTransfer[i];
  }

  if(subwire.elements()[ele].type() == tlv::Name){
     len =  mutateName(subwire.elements()[ele], Seed, bytes1, Size, MaxSize);
  }
  else{
     size_t freespace = MaxSize-Size-8;
     if(MaxSize <= Size+8)
        freespace = 0;
     len =  mutateNonsubTLVfield(subwire, subwire.elements()[ele].type(), Seed, bytes1, Size, MaxSize);

  }
  size_t totalLength = 0;

  EncodingEstimator estimator;
  Name del;
  size_t estimatedSize = del.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);
  for(i=1;i<=wire.elements_size();i++){
     subwire = wire.elements()[wire.elements_size()-i];
     size_t delLen = 0;
     if(field == wire.elements_size()-i && ele == 1){
        delLen += encoder.prependByteArrayBlock(subwire.elements()[1].type(),  bytes1, len);
      }
      else{
        delLen += encoder.prependByteArrayBlock(subwire.elements()[1].type(), subwire.elements()[1].value(), subwire.elements()[1].value_size());
      }
      if(field == wire.elements_size()-i && ele == 0){
                delLen += encoder.prependByteArrayBlock(subwire.elements()[0].type(),  bytes1, len);

    }
      else {
           delLen += encoder.prependByteArrayBlock(subwire.elements()[0].type(), subwire.elements()[0].value(), subwire.elements()[0].value_size());
      }
      delLen += encoder.prependVarNumber(delLen);
      delLen += encoder.prependVarNumber(tlv::LinkDelegation);
      totalLength += delLen;
  }
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::ForwardingHint);
  len = encoder.block().value_size();
  byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++)
     Dat[i]= byteTransfer[i];
  free(bytes1);
  return len;
}

size_t deleteFHDel(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  wire.parse();
  size_t estimatedSize = name.wireEncode(estimator);
  uint32_t deletions = rand()%(wire.elements_size());
  uint32_t position = rand()%(wire.elements_size());
  EncodingBuffer encoder(estimatedSize, 0);
  size_t i;
  
  for(i=0;i<wire.elements_size();i++){
     if(i>=position && i<(position+deletions))
        continue;
     totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::ForwardingHint);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }
  return len;
}

size_t addFHDel(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if((MaxSize-10) <= (Size))return wire.value_size();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  wire.parse();
  size_t estimatedSize = name.wireEncode(estimator);
  uint32_t additions = (rand()%((MaxSize-Size)/10));

  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t bytes1[3] = {8,1, 255};
  uint8_t bytes2[1] = {255};

  size_t i;

  for(i=0;i<wire.elements_size();i++){
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  for(i=0;i<additions;i++){
     size_t delLen = 0;
 
     delLen += encoder.prependByteArrayBlock(tlv::Name,  bytes1, 3);
     delLen += encoder.prependByteArrayBlock(tlv::LinkPreference,  bytes2, 1);
      
     delLen += encoder.prependVarNumber(delLen);
     delLen += encoder.prependVarNumber(tlv::LinkDelegation);
     totalLength += delLen;
  }
 

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::ForwardingHint);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }
  return len;
}

size_t suffleFHDel(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  wire.parse();
  if(wire.elements_size() == 1)return wire.value_size();
  size_t i, totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  size_t estimatedSize = name.wireEncode(estimator);
  uint32_t suffles = (rand()%(wire.elements_size()/2));
  int* pos = ( int*) malloc(sizeof(int)*wire.elements_size());
  uint32_t suffleIndex = 0;

  while(suffleIndex<wire.elements_size()){
     pos[suffleIndex] = suffleIndex;
     suffleIndex++;
  }

  suffleIndex = 0;
  while(suffleIndex<suffles){
    uint32_t temp;
    int first = (rand()%(wire.elements_size()));
    int second = (rand()%(wire.elements_size()));
    temp = pos[first];
    pos[first]=pos[second];
    pos[second] = temp;
     suffleIndex++;
  }

  EncodingBuffer encoder(estimatedSize, 0);

  for(i=0;i<wire.elements_size();i++){
        totalLength += encoder.appendByteArrayBlock(wire.elements()[pos[i]].type(), wire.elements()[pos[i]].value(), wire.elements()[pos[i]].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::LinkDelegation);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }

  free(pos);
  return len;
}

size_t changeFHDelTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if((MaxSize-5) <= (Size))return wire.value_size();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  wire.parse();
  size_t estimatedSize = name.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
  bytes[0] = 255;

  uint64_t newTLV = (rand()%(std::numeric_limits<uint64_t>::max()));
  size_t component = (rand()%(wire.elements_size()));

  for(size_t i=0;i<wire.elements_size();i++){
        if(i == component){
           size_t delLen = 0;
           size_t dels = wire.elements()[i].elements_size();
           delLen += encoder.prependByteArrayBlock(newTLV,  bytes, 1);
           for(size_t k = 1; k<=dels;k++){
              delLen += encoder.prependByteArrayBlock(wire.elements()[i].elements()[dels-k].type(), wire.elements()[i].elements()[dels-k].value(), wire.elements()[i].elements()[dels-k].value_size());
           }
           delLen += encoder.prependVarNumber(delLen);
           delLen += encoder.prependVarNumber(tlv::LinkDelegation);
           totalLength += delLen;
        }
        else
           totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::LinkDelegation);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(size_t i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }

  free(bytes);
  return len;
}

size_t mutateName(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  uint32_t mutationType = (rand()%5);
if(mutationType < TLVchange){
     switch(mutationType){
        case deletion :
         return deleteNameCom(wire, Seed, Dat, Size, MaxSize);
           break;
        case addition :
           return addNameCom(wire, Seed, Dat, Size, MaxSize);
           break;
        case suffle :
           return suffleNameCom(wire, Seed, Dat, Size, MaxSize); 
           break;
        case TLVchange :
           return changeNameComTLV(wire, Seed, Dat, Size, MaxSize);
           break;
     }
     return 0;
  }
  if (wire.elements_size() == 0 ) return wire.value_size();
  uint32_t field = randomlyChooseSubField(wire, Seed);
  size_t len;
  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*4096);
  size_t i;
  wire.parse();
   
  const uint8_t* byteTransfer = wire.elements()[field].value();
  for(i = 0; i < wire.elements()[field].value_size(); i++)
     bytes1[i] = byteTransfer[i];
  size_t freespace = MaxSize - Size -8;
     if(MaxSize <= Size+8)
        freespace = 0;
  len =  LLVMFuzzerMutate(bytes1, wire.elements()[field].value_size(),freespace+wire.elements()[field].value_size());

  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  size_t estimatedSize = name.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  for(i=0;i<wire.elements_size();i++){  
     if(field == i)
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  bytes1, len);
     else
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Name);
  len = encoder.block().value_size();
  byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }

  free(bytes1);
  return len;

}

size_t deleteNameCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  wire.parse();
  if(wire.elements_size() <= 1) return wire.value_size();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  size_t estimatedSize = name.wireEncode(estimator);
  uint32_t deletions = rand()%(wire.elements_size()+1);
  uint32_t position = rand()%(wire.elements_size());
  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
  bytes[0] = 255;

  size_t i;
  
  for(i=0;i<wire.elements_size();i++){
        if(i>=position && i<(position+deletions) && wire.elements()[i].type()!=2) continue;
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Name);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
     }

  free(bytes);
  return len;
}

size_t addNameCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if((MaxSize-8) <= (Size))return wire.value_size();

  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  wire.parse();
  size_t estimatedSize = name.wireEncode(estimator);
  uint32_t additions = (rand()%((MaxSize-Size)/3));
  additions = 1;
  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
  bytes[0] = 255;
     
  size_t i;
  
  for(i=0;i<wire.elements_size();i++){
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  for(i=0;i<additions;i++){
        totalLength += encoder.appendByteArrayBlock(tlv::GenericNameComponent, bytes, 1);
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Name);
  size_t len = encoder.block().value_size();
  encoder.block().parse();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
     }

  free(bytes);
  return len;
}

size_t suffleNameCom(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if(wire.elements_size() <= 1)return wire.value_size();
  wire.parse();
  size_t i, totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  size_t estimatedSize = name.wireEncode(estimator);
  uint32_t suffles = (rand()%(wire.elements_size()/2));
  int* pos = ( int*) malloc(sizeof(int)*wire.elements_size());
  uint32_t suffleIndex = 0;

  while(suffleIndex<wire.elements_size()){
     pos[suffleIndex] = suffleIndex;
     suffleIndex++;   
  }

  suffleIndex = 0;
  while(suffleIndex<suffles){
    uint32_t temp;
    int first = (rand()%(wire.elements_size()));
    int second = (rand()%(wire.elements_size()));
    temp = pos[first];
    pos[first]=pos[second];
    pos[second] = temp;
     suffleIndex++;
  }

  EncodingBuffer encoder(estimatedSize, 0);

  for(i=0;i<wire.elements_size();i++){
        totalLength += encoder.appendByteArrayBlock(wire.elements()[pos[i]].type(), wire.elements()[pos[i]].value(), wire.elements()[pos[i]].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Name);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }

  free(pos);
  return len;
}

size_t changeNameComTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  wire.parse();
  size_t estimatedSize = name.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  uint32_t newTLV = (rand()%(std::numeric_limits<uint32_t>::max()));
  size_t component;
  if(wire.elements_size() <= 1) return wire.value_size();//component = 0;
  else {
     do{
        component = (rand()%(wire.elements_size()));
     }
     while(wire.elements()[component].type()==2); 
  }
  for(size_t i=0;i<wire.elements_size();i++){
        if(i == component){
           totalLength += encoder.appendByteArrayBlock(newTLV, wire.elements()[i].value(), wire.elements()[i].value_size());
        }
        else
           totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::Name);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(size_t i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }
  return len;
}

size_t mutateSignatureInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  uint32_t mutationType = 1+(rand()%4);
  if(mutationType != fieldmutation){
     switch(mutationType){
        case deletion :
           return deleteSigInfo(wire, Seed, Dat, Size, MaxSize);
           break;
        case addition :
           return addSigInfo(wire, Seed, Dat, Size, MaxSize);
           break;
        case suffle :
           return suffleSigInfo(wire, Seed, Dat, Size, MaxSize);
           break;
        case TLVchange :
           return changeSigInfoTLV(wire, Seed, Dat, Size, MaxSize);
           break;
     }
     return 0;
  }
  uint32_t field = randomlyChooseSubField(wire, Seed);
  size_t len=0;
  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*4096);
  size_t i;
  wire.parse();
  Block::element_const_iterator element = wire.find(field);
  bool addExtra = false;
  if (element == wire.elements_end()){
     if( field < 255){
        wire = createField(wire, field);
        wire.parse();
        element = wire.find(field);
     }
     else {
        addExtra = true;
        bytes1[0] = 255;
     }
  }
  size_t pos = 0;
  bool multicopies = false;
  if(addExtra){
     size_t freespace = MaxSize-Size-8;
     if(MaxSize <= Size+8)
        freespace = 0;
     len =  LLVMFuzzerMutate(bytes1, 1,freespace+1);
  }
  else {
     Block::element_const_iterator element =  wire.elements_begin();
     int copies = 0;
     while(element !=  wire.elements_end()){
        if(element->type() == field)
           copies++; 
        element++;
     }
     if(copies>1){
        int randCopy = 1+rand()%copies;
        element =  wire.elements_begin(); 
        copies = 0;
        bool found = false;
        while(!found){
           if(element->type() == field)
              copies++; 
              if(copies == randCopy){
                 found = true;
                 continue;
              }
            element++;
            pos++;
        }
        multicopies = true;
     }
     else {
        element = wire.find(field);      
     }
     Block subwire = *element;
  const uint8_t* byteTransfer = subwire.value();
     for(i = 0; i < subwire.value_size(); i++){
        bytes1[i] = byteTransfer[i];
     }

     if(field == tlv::KeyLocator && copies == 1){
        if(subwire.value_size()<=1){
         len = 0;
        }
        else {
           len = mutateKeyLocator(subwire, Seed, bytes1, Size, MaxSize);
        }
     } 
     else if(field == tlv::ValidityPeriod){
        return wire.value_size();
     }
     else {
        len = mutateNonsubTLVfield(wire, field, Seed, bytes1, Size, MaxSize);
     }
  }
  size_t totalLength = 0;
  EncodingEstimator estimator;
  SignatureInfo sigInfo(tlv::DigestSha256);
  size_t estimatedSize = sigInfo.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  for(i=0;i<wire.elements_size();i++){
     if(field == wire.elements()[i].type() && (!multicopies || pos == i)){
        size_t temp = encoder.appendByteArrayBlock(wire.elements()[i].type(),  bytes1, len); 
        totalLength += temp;
     }
     else
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  if(addExtra)
     totalLength += encoder.appendByteArrayBlock(field,  bytes1, len);
  len = totalLength;
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::SignatureInfo);
  const uint8_t* bytes2 = encoder.block().value();
  if(totalLength>4096) return wire.value_size();
  for(size_t j = 0; j < encoder.block().value_size(); j++){
     Dat[j] = bytes2[j];
  }
 free(bytes1);
 return len;
}

size_t deleteSigInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  wire.parse();
  if(wire.elements_size() <= 1) return wire.value_size();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  MetaInfo metainfo;
  size_t estimatedSize = metainfo.wireEncode(estimator);
  uint32_t deletions = rand()%(wire.elements_size()+1);
  uint32_t position = 1+rand()%(wire.elements_size()-1);
  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
  bytes[0] = 255;
  size_t i;

  for(i=0;i<wire.elements_size();i++){
        if(i>=position && i<(position+deletions)) continue;
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::SignatureInfo);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
     }

  free(bytes);
  return len;
}

size_t addSigInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if((MaxSize-8) <= (Size))return wire.value_size();
  size_t len =1, totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  wire.parse();
  size_t estimatedSize = name.wireEncode(estimator);
  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
  bytes[0] = 255;
  uint32_t sigInfoFields [7]= {tlv::SignatureType, tlv::KeyLocator, tlv::AdditionalDescription, tlv::DescriptionEntry, tlv::DescriptionKey, tlv::DescriptionValue, tlv::ValidityPeriod} ;
  uint32_t field = rand()%6;
  if(sigInfoFields[field] ==  tlv::KeyLocator)
       len = 0;
  size_t i;

  for(i=0;i<wire.elements_size();i++){
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }
        totalLength += encoder.appendByteArrayBlock(sigInfoFields[field], bytes, len);

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::SignatureInfo);
  len = encoder.block().value_size();
  encoder.block().parse();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
     }

  free(bytes);
  return len;
}

size_t suffleSigInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  wire.parse();
  if(wire.elements_size() <= 2)return wire.value_size();
  //srand(Seed);
  wire.parse();
  size_t i, totalLength = 0;
  EncodingEstimator estimator;
  MetaInfo metaInfo;
  size_t estimatedSize = metaInfo.wireEncode(estimator);
  uint32_t suffles = (rand()%(wire.elements_size()/2));
  int* pos = ( int*) malloc(sizeof(int)*wire.elements_size());
  uint32_t suffleIndex = 0;

  while(suffleIndex<wire.elements_size()){
     pos[suffleIndex] = suffleIndex;
     suffleIndex++;
  }

  suffleIndex = 0;
  while(suffleIndex<suffles){
    uint32_t temp;
    int first = 2+rand()%(wire.elements_size()-2);
    int second = 2+rand()%(wire.elements_size()-2);
    temp = pos[first];
    pos[first]=pos[second];
    pos[second] = temp;
     suffleIndex++;
  }

  EncodingBuffer encoder(estimatedSize, 0);

  for(i=0;i<wire.elements_size();i++){
        totalLength += encoder.appendByteArrayBlock(wire.elements()[pos[i]].type(), wire.elements()[pos[i]].value(), wire.elements()[pos[i]].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::SignatureInfo);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }
  free(pos);
  return len;
}

size_t changeSigInfoTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  //srand(Seed);
  size_t totalLength = 0;
  EncodingEstimator estimator;
  MetaInfo metaInfo;
  wire.parse();
  size_t estimatedSize = metaInfo.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);
  uint32_t newTLV = (rand()%(std::numeric_limits<uint32_t>::max()));
  size_t component;
  if(wire.elements_size() <= 1) return wire.value_size();
  else component = 1+rand()%(wire.elements_size()-1);

  for(size_t i=0;i<wire.elements_size();i++){
        if(i == component)
           totalLength += encoder.appendByteArrayBlock(newTLV, wire.elements()[i].value(), wire.elements()[i].value_size());
        else
           totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::SignatureInfo);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(size_t i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }
  return len;
}

size_t mutateKeyLocator(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  uint32_t mutationType = (rand()%5);
  mutationType = fieldmutation;
  if(mutationType != fieldmutation){
     switch(mutationType){
        case deletion :
  //         return deleteNameCom(wire, Seed, Dat, Size, MaxSize);
           break;
        case addition :
    //       return addNameCom(wire, Seed, Dat, Size, MaxSize);
           break;
        case suffle :
      //     return suffleNameCom(wire, Seed, Dat, Size, MaxSize);
           break;
        case TLVchange :
        //   return changeNameComTLV(wire, Seed, Dat, Size, MaxSize);
           break;
     }
     return 0;
  }
  //wire.parse();
  if (wire.elements_size() == 0 ) return wire.value_size();
  size_t len;
  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*4096);
  size_t i;
  int change = 0; 
  const uint8_t* byteTransfer = wire.elements()[0].value();
  for(i = 0; i < wire.elements()[0].value_size(); i++)
     bytes1[i] = byteTransfer[i];
  if(wire.elements()[0].type() == tlv::Name){  
     len = mutateName(wire.elements()[0], Seed, bytes1, Size, MaxSize);  
     change = rand()%2;
  }
  else {
    len = mutateNonsubTLVfield(wire, wire.elements()[0].type(), Seed, bytes1, Size, MaxSize);
     len = 3;
  }
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  size_t estimatedSize = name.wireEncode(estimator);
  EncodingBuffer encoder(estimatedSize, 0);
  if(change == 1){
     for(size_t j = 0; j<3;j++)
        bytes1[j] = 1;
  }
  for(i=0;i<wire.elements_size();i++){
        if(change)
           totalLength += encoder.appendByteArrayBlock(tlv::KeyDigest,  bytes1, 3);
        else 
           totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  bytes1, len);
  }
  len = totalLength;
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::KeyLocator);
  const uint8_t* bytes2 = encoder.block().value();
  for(size_t j = 0; j < encoder.block().value_size(); j++){
    Dat[j] = bytes2[j];
  } 
 free(bytes1);
 return len;
}

size_t mutateMetaInfo(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize, int ensureSatisfaction){
  uint32_t mutationType = (rand()%5);
   if(mutationType != fieldmutation){
     switch(mutationType){
        case deletion :
        return deleteMeta(wire, Seed, Dat, Size, MaxSize);
           break;
        case addition :
           return addMeta(wire, Seed, Dat, Size, MaxSize);
           break;
        case suffle :
           return suffleMeta(wire, Seed, Dat, Size, MaxSize);
           break;
        case TLVchange :
           return changeMetaTLV(wire, Seed, Dat, Size, MaxSize);
           break;
     }
     return 0;
  }

  uint32_t field;
  do{
  field = randomlyChooseSubField(wire, Seed);
  }while(field == tlv::FreshnessPeriod &&  ensureSatisfaction > 10);
  size_t len=0;
  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*4096);
  size_t i;
  wire.parse();
  Block::element_const_iterator element = wire.find(field);

  if (element == wire.elements_end()){
     wire = createField(wire, field);
     wire.parse();
     element = wire.find(field);
  }
  element =  wire.elements_begin();
  bool multicopies = false;
  int copies = 0;
  size_t pos = 0;
  while(element !=  wire.elements_end()){
     if(element->type() == field)
        copies++;
     element++;
  }
  if(copies>1){
     int randCopy = 1+rand()%copies;
     element =  wire.elements_begin();
     copies = 0;
     bool found = false;
     while(!found){
        if(element->type() == field)
           copies++;
           if(copies == randCopy){
              found = true;
              continue;
           }
         element++;
         pos++;
     }
     multicopies = true;
  }
  else {
     element = wire.find(field);
  }

  Block subwire = *element;
  const uint8_t* byteTransfer = element->value();
  for(i = 0; i < element->value_size(); i++){
     bytes1[i] = byteTransfer[i];
  }
  if(field == tlv::FinalBlockId){
     len = mutateFinalBlockId(subwire, Seed, bytes1, Size, MaxSize);
  }
  else {
     len = mutateNonsubTLVfield(wire, field, Seed, bytes1, Size, MaxSize);
  }
  size_t totalLength = 0;
  // ForwardingHint
  EncodingEstimator estimator;
  SignatureInfo sigInfo(tlv::DigestSha256);
  size_t estimatedSize = sigInfo.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  for(i=0;i<wire.elements_size();i++){
     if(field == wire.elements()[i].type() && (!multicopies || pos == i)){
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  bytes1, len);
     }else
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  len = totalLength;
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::MetaInfo);
  const uint8_t* bytes2 = encoder.block().value();
  for(size_t j = 0; j < encoder.block().value_size(); j++){
     Dat[j] = bytes2[j];
  }
 free(bytes1);
 return len;
}
 
size_t deleteMeta(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  wire.parse();
  if(wire.elements_size() == 0) return wire.value_size();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  MetaInfo metainfo;
  size_t estimatedSize = metainfo.wireEncode(estimator);
  uint32_t deletions = rand()%(wire.elements_size()+1);
  uint32_t position = rand()%(wire.elements_size());
  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
  bytes[0] = 255;

  size_t i;

  bool firstFBID = true;
  for(i=0;i<wire.elements_size();i++){
        if(i>=position && i<(position+deletions)) continue;
        if(wire.elements()[i].type() == tlv::FinalBlockId && wire.elements()[i].elements_size() == 0 && firstFBID){
           uint8_t bytes[3] = {8, 1, 255};
           totalLength += encoder.appendByteArrayBlock(tlv::FinalBlockId, bytes, 3);
           firstFBID=false;
        }
        else
           totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::MetaInfo);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
     }

  free(bytes);
  return len;
}

size_t addMeta(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if((MaxSize-8) <= (Size))return wire.value_size();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  MetaInfo metaInfo;
  wire.parse();
  size_t estimatedSize = metaInfo.wireEncode(estimator);
  uint32_t additions = (rand()%((MaxSize-Size)/3));
  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
  bytes[0] = 255;
  uint32_t metaInfoFields [3]={tlv::ContentType, tlv::FreshnessPeriod, tlv::FinalBlockId};
  size_t i;
  bool firstFBID = true;

  for(i=0;i<wire.elements_size();i++){
        if(wire.elements()[i].type() == tlv::FinalBlockId && firstFBID) firstFBID=false;
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());  
}
  for(i=0;i<additions;i++){
     uint32_t field = rand()%3;
     if(metaInfoFields[field] == tlv::FinalBlockId && firstFBID){
        uint8_t bytes[3] = {8, 1, 255};
        totalLength += encoder.appendByteArrayBlock(tlv::FinalBlockId, bytes, 3);
        firstFBID=false;
     }
     else
        totalLength += encoder.appendByteArrayBlock(metaInfoFields[field], bytes, 1);
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::MetaInfo);
  size_t len = encoder.block().value_size();
  encoder.block().parse();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
     }

  free(bytes);
  return len;
}

size_t suffleMeta(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  wire.parse();
  if(wire.elements_size() <= 1)return wire.value_size();
  wire.parse();
  size_t i, totalLength = 0;
  EncodingEstimator estimator;
  MetaInfo metaInfo;
  size_t estimatedSize = metaInfo.wireEncode(estimator);
  uint32_t suffles = (rand()%(wire.elements_size()/2));
  int* pos = ( int*) malloc(sizeof(int)*wire.elements_size());
  uint32_t suffleIndex = 0;

  while(suffleIndex<wire.elements_size()){
     pos[suffleIndex] = suffleIndex;
     suffleIndex++;
  }
  suffleIndex = 0;
  while(suffleIndex<suffles){
    uint32_t temp;
    int first = (rand()%(wire.elements_size()));
    int second = (rand()%(wire.elements_size()));
    temp = pos[first];
    pos[first]=pos[second];
    pos[second] = temp;
     suffleIndex++;
  }

  EncodingBuffer encoder(estimatedSize, 0);
  bool firstFBID = true;
  for(i=0;i<wire.elements_size();i++){
        if(wire.elements()[pos[i]].type() == tlv::FinalBlockId && wire.elements()[pos[i]].elements_size() == 0 && firstFBID){
           uint8_t bytes[3] = {8, 1, 255};
           totalLength += encoder.appendByteArrayBlock(tlv::FinalBlockId, bytes, 3);
           firstFBID=false;
        }
        else 
        {
        totalLength += encoder.appendByteArrayBlock(wire.elements()[pos[i]].type(), wire.elements()[pos[i]].value(), wire.elements()[pos[i]].value_size());
        }
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::MetaInfo);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }
  free(pos);
  return len;
}

size_t changeMetaTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  size_t totalLength = 0;
  EncodingEstimator estimator;
  MetaInfo metaInfo;
  wire.parse();
  size_t estimatedSize = metaInfo.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  uint32_t newTLV = (rand()%(std::numeric_limits<uint32_t>::max()));
  size_t component;
  if(wire.elements_size() <= 1) component = 0;
  else component = (rand()%(wire.elements_size()));

  for(size_t i=0;i<wire.elements_size();i++){
        if(i == component)
           totalLength += encoder.appendByteArrayBlock(newTLV, wire.elements()[i].value(), wire.elements()[i].value_size());
        else
           totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::MetaInfo);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(size_t i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }

  return len;
}

size_t mutateFinalBlockId(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if (wire.elements_size() == 0 ) return wire.value_size();
  uint32_t field = randomlyChooseSubField(wire, Seed);
  size_t len;
  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*4096);
  size_t i;
  wire.parse();

  const uint8_t* byteTransfer = wire.elements()[field].value();
  for(i = 0; i < wire.elements()[field].value_size(); i++)
     bytes1[i] = byteTransfer[i];
  size_t freespace = MaxSize - Size -8;
     if(MaxSize <= Size+8)
        freespace = 0;
  len =  LLVMFuzzerMutate(bytes1, wire.elements()[field].value_size(),freespace+wire.elements()[field].value_size());

  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  size_t estimatedSize = name.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  for(i=0;i<wire.elements_size();i++){
     if(field == i)
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  bytes1, len);
     else
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::FinalBlockId);
  len = encoder.block().value_size();
  byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }

  free(bytes1);
  return len;
}

size_t mutateAppParam(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  uint32_t mutationType = (rand()%2);
   if(mutationType == deletion){return 0;}
  wire.parse();

  uint32_t field = randomlyChooseSubField(wire, Seed);
  size_t len=0;
  uint8_t* bytes1 = ( uint8_t*) malloc(sizeof(uint8_t)*4096);
  size_t i;
  Block subwire = wire.elements()[field];
  const uint8_t* byteTransfer = subwire.value();
  for(i = 0; i < subwire.value_size(); i++){
     bytes1[i] = byteTransfer[i];
  }
  len = mutateNonsubTLVfield(wire, subwire.type(), Seed, bytes1, Size, MaxSize);
  size_t totalLength = 0;
  EncodingEstimator estimator;
  Name name;
  size_t estimatedSize = name.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  for(i=0;i<wire.elements_size();i++){
     if(field == i){
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  bytes1, len);
     }else
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(),  wire.elements()[i].value(), wire.elements()[i].value_size());
  }
  len = totalLength;
  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::ApplicationParameters);
  const uint8_t* bytes2 = encoder.block().value();
  for(size_t j = 0; j < encoder.block().value_size(); j++){
     Dat[j] = bytes2[j];
  }
 free(bytes1);
 return len;
}

size_t deleteAppParam(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  wire.parse();
  if(wire.elements_size() == 0) return wire.value_size();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  MetaInfo metainfo;
  size_t estimatedSize = metainfo.wireEncode(estimator);
  uint32_t deletions = rand()%(wire.elements_size()+1);
  uint32_t position = rand()%(wire.elements_size());
  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
  bytes[0] = 255;

  size_t i;

  bool firstFBID = true;
  for(i=0;i<wire.elements_size();i++){
        if(i>=position && i<(position+deletions)) continue;
        if(wire.elements()[i].type() == tlv::FinalBlockId && wire.elements()[i].elements_size() == 0 && firstFBID){
           uint8_t bytes[3] = {8, 1, 255};
           totalLength += encoder.appendByteArrayBlock(tlv::FinalBlockId, bytes, 3);
           firstFBID=false;
        }
        else
           totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::MetaInfo);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
     }

  free(bytes);
  return len;
}
size_t addAppParam(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  if((MaxSize-8) <= (Size))return wire.value_size();
  size_t totalLength = 0;
  EncodingEstimator estimator;
  MetaInfo metaInfo;
  wire.parse();
  size_t estimatedSize = metaInfo.wireEncode(estimator);
  uint32_t additions = (rand()%((MaxSize-Size)/3));
  EncodingBuffer encoder(estimatedSize, 0);
  uint8_t* bytes = ( uint8_t*) malloc(sizeof(uint8_t));
  bytes[0] = 255;
  uint32_t metaInfoFields [3]={tlv::ContentType, tlv::FreshnessPeriod, tlv::FinalBlockId};
  size_t i;
  bool firstFBID = true;

  for(i=0;i<wire.elements_size();i++){
        if(wire.elements()[i].type() == tlv::FinalBlockId && firstFBID) firstFBID=false;
        totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
}
  for(i=0;i<additions;i++){
     uint32_t field = rand()%3;
     if(metaInfoFields[field] == tlv::FinalBlockId && firstFBID){
        uint8_t bytes[3] = {8, 1, 255};
        totalLength += encoder.appendByteArrayBlock(tlv::FinalBlockId, bytes, 3);
        firstFBID=false;
     }
     else
        totalLength += encoder.appendByteArrayBlock(metaInfoFields[field], bytes, 1);
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::MetaInfo);
  size_t len = encoder.block().value_size();
  encoder.block().parse();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
     }

  free(bytes);
  return len;
}
size_t suffleAppParam(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  wire.parse();
  if(wire.elements_size() <= 1)return wire.value_size();
  wire.parse();
  size_t i, totalLength = 0;
  EncodingEstimator estimator;
  MetaInfo metaInfo;
  size_t estimatedSize = metaInfo.wireEncode(estimator);
  uint32_t suffles = (rand()%(wire.elements_size()/2));
  int* pos = ( int*) malloc(sizeof(int)*wire.elements_size());
  uint32_t suffleIndex = 0;

  while(suffleIndex<wire.elements_size()){
     pos[suffleIndex] = suffleIndex;
     suffleIndex++;
  }
  suffleIndex = 0;
  while(suffleIndex<suffles){
    uint32_t temp;
    int first = (rand()%(wire.elements_size()));
    int second = (rand()%(wire.elements_size()));
    temp = pos[first];
    pos[first]=pos[second];
    pos[second] = temp;
     suffleIndex++;
  }

  EncodingBuffer encoder(estimatedSize, 0);
  bool firstFBID = true;
  for(i=0;i<wire.elements_size();i++){
        if(wire.elements()[pos[i]].type() == tlv::FinalBlockId && wire.elements()[pos[i]].elements_size() == 0 && firstFBID){
           uint8_t bytes[3] = {8, 1, 255};
           totalLength += encoder.appendByteArrayBlock(tlv::FinalBlockId, bytes, 3);
           firstFBID=false;
        }
        else
        {
        totalLength += encoder.appendByteArrayBlock(wire.elements()[pos[i]].type(), wire.elements()[pos[i]].value(), wire.elements()[pos[i]].value_size());
        }
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::MetaInfo);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }
  free(pos);
  return len;
}
size_t changeAppParamTLV(Block wire, unsigned int Seed, uint8_t* Dat, size_t Size, size_t MaxSize){
  size_t totalLength = 0;
  EncodingEstimator estimator;
  MetaInfo metaInfo;
  wire.parse();
  size_t estimatedSize = metaInfo.wireEncode(estimator);

  EncodingBuffer encoder(estimatedSize, 0);

  uint32_t newTLV = (rand()%(std::numeric_limits<uint32_t>::max()));
  size_t component;
  if(wire.elements_size() <= 1) component = 0;
  else component = (rand()%(wire.elements_size()));

  for(size_t i=0;i<wire.elements_size();i++){
        if(i == component)
           totalLength += encoder.appendByteArrayBlock(newTLV, wire.elements()[i].value(), wire.elements()[i].value_size());
        else
           totalLength += encoder.appendByteArrayBlock(wire.elements()[i].type(), wire.elements()[i].value(), wire.elements()[i].value_size());
  }

  totalLength += encoder.prependVarNumber(totalLength);
  totalLength += encoder.prependVarNumber(tlv::MetaInfo);
  size_t len = encoder.block().value_size();
  const uint8_t* byteTransfer = encoder.block().value();
  for(size_t i = 0; i < len; i++){
     Dat[i]= byteTransfer[i];
  }

  return len;
}


#endif  // CUSTOM_MUTATOR*/
} // namespace ndn
#endif  // CUSTOM_MUTATOR*/


