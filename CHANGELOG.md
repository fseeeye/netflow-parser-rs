#  (2021-07-13)


### Bug Fixes

* **protocols:** add eof check for all protocols' payload parser ([9eec31f](https://gitee.com/BoleanTech/parsing-rs/commits/9eec31fc99945bb9af683e67543e674db364de2d))


### Features

* **all:** new feature: Eof & Parser Context ([3099929](https://gitee.com/BoleanTech/parsing-rs/commits/309992992c22fef36372ed742f8a4ff6cd958f5e))
* **protocols:** add input::<&'a [u8]> in PayloadError vars and add change var 'Empty' to NomPeek ([322a76a](https://gitee.com/BoleanTech/parsing-rs/commits/322a76af0f6096b200a6ac0e85f51133eb0bdd78))
* **protocols:** split modbus into req&rsp ([e2585f7](https://gitee.com/BoleanTech/parsing-rs/commits/e2585f75f20ad852ee673439989a13fbe218980d))


### BREAKING CHANGES

* **protocols:** parse stream api was changed.



