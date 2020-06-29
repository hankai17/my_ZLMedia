/*
 * Copyright (c) 2016 The ZLMediaKit project authors. All Rights Reserved.
 *
 * This file is part of ZLMediaKit(https://github.com/xiongziliang/ZLMediaKit).
 *
 * Use of this source code is governed by MIT license that can be found in the
 * LICENSE file in the root of the source tree. All contributing project authors
 * may be found in the AUTHORS file in the root of the source tree.
 */

#ifndef SRC_RTMP_RTMPPLAYERIMP_H_
#define SRC_RTMP_RTMPPLAYERIMP_H_

#include <memory>
#include <functional>
#include "Common/config.h"
#include "RtmpPlayer.h"
#include "RtmpMediaSource.h"
#include "RtmpDemuxer.h"
#include "Poller/Timer.h"
#include "Util/TimeTicker.h"
using namespace toolkit;
using namespace mediakit::Client;

namespace mediakit {

class FlvPlayerImp : public PlayerImp<FlvPlayer, FlvDemuxer> {
public:
    typedef std::shared_ptr<FlvPlayerImp> Ptr;

    FlvPlayerImp(const EventPoller::Ptr &poller) : PlayerImp<FlvPlayer, FlvDemuxer>(poller){};
    virtual ~FlvPlayerImp(){
        DebugL<<endl;
    };

protected:
    virtual void onMediaData(const FlvPacket::Ptr &frameData) { // 接受底层传过来的数据
        if(!_pFlvMediaSrc) {
            _pFlvMediaSrc = dynamic_pointer_cast<FlvMediaSource>(_pMediaSrc);
        }
        if(_pFlvMediaSrc){
            /*
            if(!_set_meta_data && !chunkData->isCfgFrame()){
                _set_meta_data = true;
                _pRtmpMediaSrc->setMetaData(TitleMeta().getMetadata());
            }
            */
            _pFlvMediaSrc->onWrite(frameData);
            if(m_flv_base_header.size() || m_first_script_tag.size()
                || m_first_video_tag.size() || m_first_audio_tag.size()) {
                _pFlvMediaSrc->m_flv_base_header = m_flv_base_header;
                if (!_pFlvMediaSrc->m_flv_script_tag.size()) {
                    _pFlvMediaSrc->m_flv_script_tag = std::move(m_first_script_tag);
                }
                if (!_pFlvMediaSrc->m_flv_audio_tag.size()) {
                    _pFlvMediaSrc->m_flv_audio_tag = std::move(m_first_audio_tag);
                }
                if (!_pFlvMediaSrc->m_flv_video_tag.size()) {
                    _pFlvMediaSrc->m_flv_video_tag = std::move(m_first_video_tag);
                }
            }
        }
        /*
        if(!_delegate){
            //这个流没有metadata
            _delegate.reset(new RtmpDemuxer());
        }
        _delegate->inputRtmp(chunkData);
        */
    }

private:
    FlvMediaSource::Ptr _pFlvMediaSrc; // 1 构造一个flvMediaSource 实现onWrite功能
    bool _set_meta_data = false;
};

class RtmpPlayerImp: public PlayerImp<RtmpPlayer,RtmpDemuxer> {
public:
    typedef std::shared_ptr<RtmpPlayerImp> Ptr;
    RtmpPlayerImp(const EventPoller::Ptr &poller) : PlayerImp<RtmpPlayer,RtmpDemuxer>(poller){};
    virtual ~RtmpPlayerImp(){
        DebugL<<endl;
    };
    float getProgress() const override{
        if(getDuration() > 0){
            return getProgressMilliSecond() / (getDuration() * 1000);
        }
        return PlayerBase::getProgress();
    };
    void seekTo(float fProgress) override{
        fProgress = MAX(float(0),MIN(fProgress,float(1.0)));
        seekToMilliSecond(fProgress * getDuration() * 1000);
    };
    void play(const string &strUrl) override {
        PlayerImp<RtmpPlayer,RtmpDemuxer>::play(strUrl);
    }
private:
    //派生类回调函数
    bool onCheckMeta(const AMFValue &val) override {
        _pRtmpMediaSrc = dynamic_pointer_cast<RtmpMediaSource>(_pMediaSrc);
        if(_pRtmpMediaSrc){
            _pRtmpMediaSrc->setMetaData(val);
            _set_meta_data = true;
        }
        _delegate.reset(new RtmpDemuxer);
        _delegate->loadMetaData(val);
        return true;
    }
    void onMediaData(const RtmpPacket::Ptr &chunkData) override {
        if(_pRtmpMediaSrc){
            if(!_set_meta_data && !chunkData->isCfgFrame()){
                _set_meta_data = true;
                _pRtmpMediaSrc->setMetaData(TitleMeta().getMetadata());
            }
            _pRtmpMediaSrc->onWrite(chunkData);
        }
        if(!_delegate){
            //这个流没有metadata
            _delegate.reset(new RtmpDemuxer());
        }
        _delegate->inputRtmp(chunkData);
    }
private:
    RtmpMediaSource::Ptr _pRtmpMediaSrc;
    bool _set_meta_data = false;
};


} /* namespace mediakit */

#endif /* SRC_RTMP_RTMPPLAYERIMP_H_ */
