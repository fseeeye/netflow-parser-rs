# [](https://gitee.com/BoleanTech/parsing-rs/compare/v0.3.4...v) (2021-08-18)



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



