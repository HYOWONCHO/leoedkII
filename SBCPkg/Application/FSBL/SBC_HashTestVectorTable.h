#ifndef __HASH_VECTOR_TABLE_
#define __HASH_VECTOR_TABLE_

typedef struct  {
  CHAR8* msg;
  CHAR8* key;
  CHAR8* answer;
  UINTN  len;
}SBCHashTestVectorMsg_t;

SBCHashTestVectorMsg_t gt_hmactv[] = {
    {
        .key = "191a700f3dc560a589f9c2ca784e970cb1e552a0e6b3df54fc1ce3c56cc446d2",
        .msg = "1948c7120a0618c544a39e5957408b89220ae398ec053039b00978adb70a6c2b6c9ce2846db58507deb5cba202a5284b0cbc829e3228e4c8040b76a3fcc3ad22566ebff021ad5a5497a99558aa54272adff2d6c25fd733c54c7285aa518a031b7dc8469e5176fd741786e3c176d6eeee44b2c94c9b9b85fa2f468c08dee8d6dc",
        .answer = "bbae3443905781e53547d5e5d566b55d1b95a99cdb85b361792e1ea6b51743e2"
    },
    {
        .key = "dcb463a13ae337414151a31aa0c3e8bab3ee781b9f3aaa869dc5b1b196abcf2b",
        .msg = "44c9bf3ae8f14cc9d6935deda3c24de69c67f0885a87c89996c47c7b3e27850ac71c2bc8c6beb038ba55cb872c1d5871fb4a4d63f148f0dd9947471b55f7d0f4ab907302e016b503c8db2e7fdc453dac8dd1fa8ed8586c621b92fd3d27d82af1962e7f305f80c3f4a72c701ddac1665cfb06df51383fa6f0c2ab8429db51fbc8",
        .answer = "d9cd8c98db4de3d7b2de43ce9be4d5a39cf111cc108b662a05629b4d914ec0d1"
    },
    {
        .key = "93e7402cb2b1b594670e656a6ca4ef247231ac09b7cce194d76e3919e4b072aa",
        .msg = "cb2a072d74a5749481030ee46edce28c471ef412c8a4814ac40b87cbc3c188a3ef5e8a4a313862d59731326cf9d431fedca1aa3396a448a3b34d9045987baf2a66da766b216fa36012716212695b13f3273f4ecd3b5d24f9ebf4a8d17658af67f845d3788d73be9bb96aa5be089812d3f1a1e7c700f6a0b435a9d857a7800ec4",
        .answer = "728c32bc47ece847718d36881646eef382c1f8b7fc5625f87c4eaf60d0a7a6d3"
    }
};



#endif
