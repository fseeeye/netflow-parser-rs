# [](https://gitee.com/BoleanTech/parsing-rs/compare/v0.5.0...v) (2021-11-11)



# [0.5.0](https://gitee.com/BoleanTech/parsing-rs/compare/v0.4.1...v0.5.0) (2021-11-11)


### Bug Fixes

* **benchmark:** fix benchmark error ([7a7406a](https://gitee.com/BoleanTech/parsing-rs/commits/7a7406ac6540bd13d8337e1430cc7fa38d26eb49))
* **protocol:** improve BACnet protocol ([a2cbf93](https://gitee.com/BoleanTech/parsing-rs/commits/a2cbf935dc210810823884247bc0158382541609))


### Features

* **all:** convert to Rust 2021 ([18c9185](https://gitee.com/BoleanTech/parsing-rs/commits/18c9185fd0033a5fbe445c01fd573c3bb65c771c))
* **all:** update to version 0.5.0🎉 ([51dc8d6](https://gitee.com/BoleanTech/parsing-rs/commits/51dc8d6c4e43648a9945b5b03f073c4bc1bf6859))
* **protocol:** add DNP3 ([051711a](https://gitee.com/BoleanTech/parsing-rs/commits/051711add5284a2798a4a5efa6768de20f55374d))
* **protocol:** add IEC60870-104 (with IEC60870-ASDU) ([1b8da0b](https://gitee.com/BoleanTech/parsing-rs/commits/1b8da0b322e937f2734ecd8db18d9aca66a9d2ad))
* **protocol:** add Opcua protocol ([ede6652](https://gitee.com/BoleanTech/parsing-rs/commits/ede665246239e339dc46641a1f1ab4c88bceff36))
* **protocol:** init BACnet protocol ([33f0751](https://gitee.com/BoleanTech/parsing-rs/commits/33f075134f411edc25f809a395cb6ad80efd3e7a))
* **protocol:** initially complete "S7comm" ([bc0934f](https://gitee.com/BoleanTech/parsing-rs/commits/bc0934f63123e4e59aea49a3de44ad5fe75d2e22))
* split ISO-on-TCP & add slice built-in parser ([ed00c92](https://gitee.com/BoleanTech/parsing-rs/commits/ed00c9214d5608e56ab571a3e5105326765948dc))



## [0.4.1](https://gitee.com/BoleanTech/parsing-rs/compare/v0.4.0...v0.4.1) (2021-09-23)


### Bug Fixes

* **protocol:** some pcaps don't include 'protocol version' in osi_pres, made a choice ([1338152](https://gitee.com/BoleanTech/parsing-rs/commits/1338152ee10c645bb6949a33ca596e91640271be))


### Features

* **feature:** add ber-tl field ([eeb4cfe](https://gitee.com/BoleanTech/parsing-rs/commits/eeb4cfe4f50095166a1cd15792b79ce8e0a3f204))
* **protocol:** add mms ([5fd0541](https://gitee.com/BoleanTech/parsing-rs/commits/5fd05410e8af7659558acf6c8720e4f3c2062eac))
* **protocol:** add mms ([59d8d94](https://gitee.com/BoleanTech/parsing-rs/commits/59d8d94596f1a8fb1e939c58d9c146ee2d09d5b6))
* **protocol:** mms ([4ae0653](https://gitee.com/BoleanTech/parsing-rs/commits/4ae065370dc4c99f80c4148b5d59ed320492a15b))
* **protocol:** mms without tag and length when output in debug mod ([beda513](https://gitee.com/BoleanTech/parsing-rs/commits/beda513c8119bc5fda98df9bd2c45be338c11f24))
* **protocol:** parse mmms without its protocol stack ([d367d31](https://gitee.com/BoleanTech/parsing-rs/commits/d367d31a5eb519b063d8dfda7ee2f8da034b9fe2))



# [0.4.0](https://gitee.com/BoleanTech/parsing-rs/compare/v0.3.4...v0.4.0) (2021-09-18)


### Bug Fixes

* **ffi:** change sth. about ffi ([df1dd8b](https://gitee.com/BoleanTech/parsing-rs/commits/df1dd8b0849d8b0231b1d52e9a5410bfd421f812))


### Features

* **rule:** include Modbus automatically generated code of ICS rule ([bbe451d](https://gitee.com/BoleanTech/parsing-rs/commits/bbe451d12d16043efb73c851b682a51a674f71d1))
* add ics-rules structure ([1c0254a](https://gitee.com/BoleanTech/parsing-rs/commits/1c0254a5d066445a16c2220c9f81bb302679e3c4))
* check rules demo ([b4409b5](https://gitee.com/BoleanTech/parsing-rs/commits/b4409b53eb3b735091317ea34683d78bff88451c))



## [0.3.4](https://gitee.com/BoleanTech/parsing-rs/compare/v0.3.3...v0.3.4) (2021-08-18)


### Features

* merge branch "vec-re" & "feature/fins" ([adb565f](https://gitee.com/BoleanTech/parsing-rs/commits/adb565f0d4a7b6947bc21e07b6277c471b7380b5))



## [0.3.3](https://gitee.com/BoleanTech/parsing-rs/compare/v0.3.2...v0.3.3) (2021-08-09)


### Features

* **benches:** add benchmark feature ([8faac3d](https://gitee.com/BoleanTech/parsing-rs/commits/8faac3d9f167897acdc3b1180a1c7b59e9916dd2))


### Reverts

* delete VecPacket & ParsersMap ([b492f2c](https://gitee.com/BoleanTech/parsing-rs/commits/b492f2c8f27eb955229f91d707179939d55689d2))



## [0.3.2](https://gitee.com/BoleanTech/parsing-rs/compare/v0.3.1...v0.3.2) (2021-08-03)


### Features

* **packet:** add stop feature for packet ([d767a1e](https://gitee.com/BoleanTech/parsing-rs/commits/d767a1e21d10d196988301e62a7e9d08fb746701))
* **protocols:** new QuinPacket with layer levels ([8e78dc1](https://gitee.com/BoleanTech/parsing-rs/commits/8e78dc190b6f1cb0cac674c4eea3b24a2bb7c60b))



## [0.3.1](https://gitee.com/BoleanTech/parsing-rs/compare/v0.3.0...v0.3.1) (2021-07-30)


### Features

* **protocols:** faster packet: QuinPacket ([840bf97](https://gitee.com/BoleanTech/parsing-rs/commits/840bf97033c80631e3c88a5ce6f500a77dff82c1))



# [0.3.0](https://gitee.com/BoleanTech/parsing-rs/compare/v0.2.0...v0.3.0) (2021-07-27)


### Features

* **parsers:** adapt parsers to new structure of package ([3398943](https://gitee.com/BoleanTech/parsing-rs/commits/3398943a629e985c56ba923146cf4585c40d8a69))
* **protocol:** new structure of package ([b125ed8](https://gitee.com/BoleanTech/parsing-rs/commits/b125ed865b86741d7dac1816e5761f673caf60c4))



# [0.2.0](https://gitee.com/BoleanTech/parsing-rs/compare/309992992c22fef36372ed742f8a4ff6cd958f5e...v0.2.0) (2021-07-20)


### Bug Fixes

* **protocols:** add eof check for all protocols' payload parser ([9eec31f](https://gitee.com/BoleanTech/parsing-rs/commits/9eec31fc99945bb9af683e67543e674db364de2d))


### Features

* **all:** new feature: Eof & Parser Context ([3099929](https://gitee.com/BoleanTech/parsing-rs/commits/309992992c22fef36372ed742f8a4ff6cd958f5e))
* **protocol:** add input::<&'a [u8]> in PayloadError vars and add change var 'Empty' to NomPeek ([322a76a](https://gitee.com/BoleanTech/parsing-rs/commits/322a76af0f6096b200a6ac0e85f51133eb0bdd78))
* **protocols:** split modbus into req&rsp ([e2585f7](https://gitee.com/BoleanTech/parsing-rs/commits/e2585f75f20ad852ee673439989a13fbe218980d))
* **protocols:** split Packet Trait and add Packet Types ([3cbd89e](https://gitee.com/BoleanTech/parsing-rs/commits/3cbd89eee0afc4c42772b12db10fbbc82c391361))


### BREAKING CHANGES

* **protocols:** parse stream api was changed.



