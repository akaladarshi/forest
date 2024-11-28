// Copyright 2019-2024 ChainSafe Systems
// SPDX-License-Identifier: Apache-2.0, MIT

use crate::utils::encoding::from_slice_with_fallback;
use cid::{
    multihash::{
        Code::{Blake2b256, Identity},
        MultihashDigest,
    },
    Cid,
};
use fvm_ipld_encoding::{to_vec, DAG_CBOR};
use ipld_core::{ipld, ipld::Ipld, serde::to_ipld};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone)]
struct TestStruct {
    name: String,
    details: cid_0_11::Cid,
}

#[test]
fn encode_new_type() {
    let details = Cid::new_v1(DAG_CBOR, Blake2b256.digest(&[1, 2, 3]));
    let details = crate::utils::cid::cid_10_to_11(&details);
    let name = "Test".to_string();
    let t_struct = TestStruct {
        name: name.clone(),
        details,
    };
    let struct_encoded = to_vec(&t_struct).unwrap();

    // Test to make sure struct can be encoded and decoded without IPLD
    let struct_decoded: TestStruct = from_slice_with_fallback(&struct_encoded).unwrap();
    assert_eq!(&struct_decoded.name, &name);
    assert_eq!(&struct_decoded.details, &details.clone());

    // Test ipld decoding
    let ipld_decoded: Ipld = from_slice_with_fallback(&struct_encoded).unwrap();
    assert_eq!(
        &ipld_decoded,
        &ipld!({"details": Ipld::Link(details), "name": "Test"})
    );
}

#[test]
fn cid_conversions_ipld() {
    let cid = Cid::new_v1(DAG_CBOR, Blake2b256.digest(&[1, 2, 3]));
    let cid = crate::utils::cid::cid_10_to_11(&cid);
    let m_s = TestStruct {
        name: "s".to_owned(),
        details: cid,
    };
    assert_eq!(
        to_ipld(m_s).unwrap(),
        ipld!({"name": "s", "details": Ipld::Link(cid) })
    );
    let serialized = to_vec(&cid).unwrap();
    let ipld = ipld!(Ipld::Link(cid));
    let ipld2 = to_ipld(cid).unwrap();
    assert_eq!(ipld, ipld2);
    assert_eq!(to_vec(&ipld).unwrap(), serialized);
    assert_eq!(to_ipld(cid).unwrap(), Ipld::Link(cid));

    // Test with identity hash (different length prefix for cbor)
    let cid = Cid::new_v1(DAG_CBOR, Identity.digest(&[1, 2]));
    let cid = crate::utils::cid::cid_10_to_11(&cid);
    let ipld = ipld!(Ipld::Link(cid));
    let ipld2 = to_ipld(cid).unwrap();
    assert_eq!(ipld, ipld2);
}
