/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (C) 2016-2019, Arizona Board of Regents.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
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
 * @author Shuo Yang
 * @author Weiwei Liu
 * @author Chavoosh Ghasemi
 */

#include "ndn-cxx/util/rtt-estimator.hpp"

namespace ndn {
namespace util {

RttEstimator::RttEstimator(const Options& options)
  : m_options(options)
  , m_sRtt(0)
  , m_rttVar(0)
  , m_rto(m_options.initialRto)
  , m_rttMin(time::nanoseconds::max())
  , m_rttMax(time::nanoseconds::min())
  , m_rttAvg(0)
  , m_nRttSamples(0)
{
  BOOST_ASSERT(m_options.alpha >= 0 && m_options.alpha <= 1);
  BOOST_ASSERT(m_options.beta >= 0 && m_options.beta <= 1);
  BOOST_ASSERT(m_options.initialRto >= 0_ns);
  BOOST_ASSERT(m_options.minRto >= 0_ns);
  BOOST_ASSERT(m_options.maxRto >= m_options.minRto);
  BOOST_ASSERT(m_options.k >= 0);
  BOOST_ASSERT(m_options.rtoBackoffMultiplier >= 1);
}

void
RttEstimator::addMeasurement(time::nanoseconds rtt, size_t nExpectedSamples,
                             optional<uint64_t> segNum)
{
  BOOST_ASSERT(nExpectedSamples > 0);

  if (m_nRttSamples == 0) { // first measurement
    m_sRtt = rtt;
    m_rttVar = m_sRtt / 2;
  }
  else {
    double alpha = m_options.alpha / nExpectedSamples;
    double beta = m_options.beta / nExpectedSamples;
    m_rttVar = time::duration_cast<time::nanoseconds>((1 - beta) * m_rttVar +
                                                      beta * time::abs(m_sRtt - rtt));
    m_sRtt = time::duration_cast<time::nanoseconds>((1 - alpha) * m_sRtt + alpha * rtt);
  }
  m_rto = clamp(m_sRtt + m_options.k * m_rttVar,
                m_options.minRto, m_options.maxRto);

  afterMeasurement({rtt, m_sRtt, m_rttVar, m_rto, segNum});

  m_rttAvg = (m_nRttSamples * m_rttAvg + rtt) / (m_nRttSamples + 1);
  m_rttMax = std::max(rtt, m_rttMax);
  m_rttMin = std::min(rtt, m_rttMin);
  m_nRttSamples++;
}

void
RttEstimator::backoffRto()
{
  m_rto = clamp(m_rto * m_options.rtoBackoffMultiplier,
                m_options.minRto, m_options.maxRto);
}

} // namespace util
} // namespace ndn
