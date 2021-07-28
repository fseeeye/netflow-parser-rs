#  (2021-07-28)


### Bug Fixes

* **protocols:** add eof check for all protocols' payload parser ([9eec31f](https://gitee.com/BoleanTech/parsing-rs/commits/9eec31fc99945bb9af683e67543e674db364de2d))


### Features

* **all:** new feature: Eof & Parser Context ([3099929](https://gitee.com/BoleanTech/parsing-rs/commits/309992992c22fef36372ed742f8a4ff6cd958f5e))
* **parsers:** adapt parsers to new structure of package ([3398943](https://gitee.com/BoleanTech/parsing-rs/commits/3398943a629e985c56ba923146cf4585c40d8a69))
* **protocol:** add input::<&'a [u8]> in PayloadError vars and add change var 'Empty' to NomPeek ([322a76a](https://gitee.com/BoleanTech/parsing-rs/commits/322a76af0f6096b200a6ac0e85f51133eb0bdd78))
* **protocol:** new structure of package ([b125ed8](https://gitee.com/BoleanTech/parsing-rs/commits/b125ed865b86741d7dac1816e5761f673caf60c4))
* **protocols:** faster packet: QuinPacket ([840bf97](https://gitee.com/BoleanTech/parsing-rs/commits/840bf97033c80631e3c88a5ce6f500a77dff82c1))
* **protocols:** split modbus into req&rsp ([e2585f7](https://gitee.com/BoleanTech/parsing-rs/commits/e2585f75f20ad852ee673439989a13fbe218980d))
* **protocols:** split Packet Trait and add Packet Types ([3cbd89e](https://gitee.com/BoleanTech/parsing-rs/commits/3cbd89eee0afc4c42772b12db10fbbc82c391361))


### BREAKING CHANGES

* **protocols:** parse stream api was changed.



#  (2021-07-13)


### Bug Fixes

* **protocols:** add eof check for all protocols' payload parser ([9eec31f](https://gitee.com/BoleanTech/parsing-rs/commits/9eec31fc99945bb9af683e67543e674db364de2d))


### Features

* **all:** new feature: Eof & Parser Context ([3099929](https://gitee.com/BoleanTech/parsing-rs/commits/309992992c22fef36372ed742f8a4ff6cd958f5e))
* **protocols:** add input::<&'a [u8]> in PayloadError vars and add change var 'Empty' to NomPeek ([322a76a](https://gitee.com/BoleanTech/parsing-rs/commits/322a76af0f6096b200a6ac0e85f51133eb0bdd78))
* **protocols:** split modbus into req&rsp ([e2585f7](https://gitee.com/BoleanTech/parsing-rs/commits/e2585f75f20ad852ee673439989a13fbe218980d))


### BREAKING CHANGES

* **protocols:** parse stream api was changed.



