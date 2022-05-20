use std::fmt;
use std::net::{Ipv4Addr, IpAddr};
use std::str::FromStr;

use ipnet::Ipv4Net;
use serde::{Serialize, Deserialize};
use serde::de::{self, Visitor};

// IPv4 with range
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Ipv4AddressVec(pub Vec<Ipv4Address>);

impl Ipv4AddressVec
{
    #[inline]
    pub fn contain(&self, target: &IpAddr) -> bool {
        match target {
            IpAddr::V4(ipv4) => self.0.iter().any(|&n| n.contain(ipv4)),
            IpAddr::V6(_) => false
        }
    }

    #[inline]
    pub fn contain_v4(&self, target: &Ipv4Addr) -> bool {
        self.0.iter().any(|&n| n.contain(target))
    }    
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(untagged)]
pub enum Ipv4Address {
    Addr(Ipv4Addr),
    CIDR(Ipv4Net),
    Range(Ipv4Range)
}

impl Ipv4Address {
    #[inline]
    pub fn contain(&self, target: &Ipv4Addr) -> bool {
        match self {
            Ipv4Address::Addr(addr) => {
                addr == target
            }
            Ipv4Address::CIDR(addr) => {
                addr.contains(target)
            }
            Ipv4Address::Range(range) => {
                range.contain(target)
            }
        }
    }
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq)]
pub struct Ipv4Range {
    pub start: Ipv4Addr,
    pub end: Ipv4Addr
}

impl Ipv4Range {
    #[inline]
    pub fn contain(&self, target: &Ipv4Addr) -> bool {
        if *target >= self.start && *target <= self.end {
            true
        } else {
            false
        }
    }
}

impl<'de> Deserialize<'de> for Ipv4Range {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de> 
    {
        struct Ipv4RangeVisitor;

        impl<'de> Visitor<'de> for Ipv4RangeVisitor {
            type Value = Ipv4Range;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("invalid start & end ipv4 address.(e.g. \"192.168.0.1\" or \"192.168.0.0/24\" or \"192.168.0.1-192.168.0.2\")")
            }

            fn visit_str<E>(self, v: &str) -> core::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                // Err(de::Error::invalid_type(de::Unexpected::Str(v), &self))

                if let Some((start_ip_str, end_ip_str)) = v.trim().split_once("-") {
                    // might be ip range
                    let start_ip = match start_ip_str.parse::<Ipv4Addr>() {
                        Ok(o) => o,
                        Err(_) => return Err(de::Error::invalid_type(de::Unexpected::Str(v), &self))
                    };

                    let end_ip = match end_ip_str.parse::<Ipv4Addr>() {
                        Ok(o) => o,
                        Err(_) => return Err(de::Error::invalid_type(de::Unexpected::Str(v), &self))
                    };

                    if end_ip <= start_ip {
                        Err(de::Error::invalid_type(de::Unexpected::Str(v), &self))
                    } else {
                        Ok(Ipv4Range {
                            start: start_ip,
                            end: end_ip
                        })
                    }
                } else {
                    Err(de::Error::invalid_type(de::Unexpected::Str(v), &self))
                }
            }
        }

        deserializer.deserialize_str(Ipv4RangeVisitor)
    }
}

// num with range
// ref: https://users.rust-lang.org/t/how-to-write-a-simple-generic-function-with-numeric-types/10943
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct NumVec<T: PartialEq + PartialOrd + Copy + FromStr + num::Zero>(pub Vec<Num<T>>);

impl<T> NumVec<T>
where
    T: PartialEq + PartialOrd + Copy + FromStr + num::Zero
{
    #[inline]
    pub fn contain(&self, target: T) -> bool {
        self.0.iter().any(|&n| n.contain(target))
    }    
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq)]
#[serde(untagged)]
pub enum Num<T: PartialEq + PartialOrd + Copy + FromStr + num::Zero> {
    Single(T),
    Range(NumRange<T>)
}

impl<T> Num<T>
where
    T: PartialOrd + Copy + FromStr + num::Zero
{
    #[inline]
    pub fn contain(&self, target: T) -> bool {
        match self {
            Self::Single(single) => {
                *single == target
            },
            Self::Range(range) => {
                range.contain(target)
            }
        }
    }
}

impl<'de, T> Deserialize<'de> for Num<T>
where
    T: PartialOrd + Copy + FromStr + num::Zero
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        deserializer.deserialize_str(NumVisitor(T::zero()))
    }
}

struct NumVisitor<T>(T);

impl<'de, T> Visitor<'de> for NumVisitor<T>
where
    T: PartialOrd + Copy + FromStr + num::Zero
{
    type Value = Num<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("invalid num.(single or range, e.g. \"31\" or \"21:31\")")
    }

    fn visit_str<E>(self, v: &str) -> core::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        if let Some((start_num_str, end_num_str)) = v.trim().split_once(":") {
            // might be ip range
            let start_num = match start_num_str.parse::<T>() {
                Ok(o) => o,
                Err(_) => return Err(de::Error::invalid_type(de::Unexpected::Str(v), &self))
            };

            let end_num = match end_num_str.parse::<T>() {
                Ok(o) => o,
                Err(_) => return Err(de::Error::invalid_type(de::Unexpected::Str(v), &self))
            };

            if end_num <= start_num {
                Err(de::Error::invalid_type(de::Unexpected::Str(v), &self))
            } else {
                Ok(Num::Range(NumRange {
                    start: start_num,
                    end: end_num
                }))
            }
        } else {
            match v.parse::<T>() {
                Ok(o) => Ok(Num::Single(o)),
                Err(_) => Err(de::Error::invalid_type(de::Unexpected::Str(v), &self))
            }
        }
    }
}

#[derive(Serialize, Debug, Clone, Copy, PartialEq)]
pub struct NumRange<T: PartialEq + PartialOrd + Copy + FromStr + num::Zero> {
    pub start: T,
    pub end: T
}

impl<T> NumRange<T>
where
    T: PartialOrd + Copy + FromStr + num::Zero
{
    #[inline]
    pub fn contain(&self, target: T) -> bool {
        if target >= self.start && target <= self.end {
            true
        } else {
            false
        }
    }
}

impl<'de, T> Deserialize<'de> for NumRange<T>
where
    T: PartialOrd + Copy + FromStr + num::Zero
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>
    {
        deserializer.deserialize_str(NumRangeVisitor(T::zero()))
    }
}

struct NumRangeVisitor<T>(T);

impl<'de, T> Visitor<'de> for NumRangeVisitor<T>
where
    T: PartialOrd + Copy + FromStr + num::Zero
{
    type Value = NumRange<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("invalid start & end num.(e.g. \"21:31\")")
    }

    fn visit_str<E>(self, v: &str) -> core::result::Result<Self::Value, E>
    where
        E: de::Error,
    {
        if let Some((start_num_str, end_num_str)) = v.trim().split_once(":") {
            // might be ip range
            let start_num = match start_num_str.parse::<T>() {
                Ok(o) => o,
                Err(_) => return Err(de::Error::invalid_type(de::Unexpected::Str(v), &self))
            };

            let end_num = match end_num_str.parse::<T>() {
                Ok(o) => o,
                Err(_) => return Err(de::Error::invalid_type(de::Unexpected::Str(v), &self))
            };

            if end_num <= start_num {
                Err(de::Error::invalid_type(de::Unexpected::Str(v), &self))
            } else {
                Ok(NumRange {
                    start: start_num,
                    end: end_num
                })
            }
        } else {
            Err(de::Error::invalid_type(de::Unexpected::Str(v), &self))
        }
    }
}
