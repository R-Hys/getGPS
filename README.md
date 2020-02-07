Intel(R) SGX を用いたGPSデータ保護の実装
================================================

# get GPS 

Introduction
------------

2019年度B4林の卒論．<br>
ドローンのフライトログの完全性担保が目標（テーマ？）-> フォレンジック対応のため<br>
ドローンがブロックチェーンネットワークにデータをブロードキャストすることで，そのネットワーク内でデータの完全性を担保することに成功している（[先行研究](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8840878&isnumber=8600701)）．<br>
しかしドローン自体が偽のデータを送る場合のケアがない．<br>
そこでセキュアプロセッサを用いた小型軽量ボックスをドローンに搭載することで，ドローンが嘘をつけないようにしよう，というのがねらい．

このレポジトリはIntel(R) SGXを用いたGPSデータ保護の実装（テスト）．<br>
PCは BOXNUC7i5BNH を使用．<br>
実際にボックスを作成したわけではないので，GPSデータは手動で pastgps.dat,newgps.dat に記入．<br>
詳細なディレクトリ構成は下に記述．


ドキュメント
------------

- [先行研究 (Livebox)](https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=8840878&isnumber=8600701)
- [詳細なIntel(R) SGXの説明](https://software.intel.com/sites/default/files/managed/7c/f1/332831-sdm-vol-3d.pdf)
- [開発時のリファレンス(Linux OS)](https://download.01.org/intel-sgx/linux-2.6/docs/Intel_SGX_Developer_Reference_Linux_2.6_Open_Source.pdf)
- [参考にしたページ](https://qiita.com/Cliffford/items/2f155f40a1c3eec288cf#intel-sgx%E5%85%A5%E9%96%80---%E5%9F%BA%E7%A4%8E%E7%9F%A5%E8%AD%98%E7%B7%A8)


ディレクトリ構成
----------------
```
.
├── App
│   ├── App.cpp
│   └── App.h
├── Enclave
│   ├── Enclave.config.xml
│   ├── Enclave.cpp
│   ├── Enclave.edl
│   ├── Enclave.h
│   ├── Enclave.lds
│   └── Enclave_private.pem
├── Include
│   └── user_types.h
├── Makefile
├── README.md
├── Seal
│   ├── Seal.config.xml
│   ├── Seal.cpp
│   ├── Seal.edl
│   ├── Seal.lds
│   └── Seal_private.pem
├── debug_mock_key.bin
└── newgps.dat
```


ビルドとテスト
----------------

- To compile and run the sample
```
  $ cd getGPS
  $ make
  $ ./app
```

- with PCL (RAは今のところ必要ないと考えているのでこっちを用いる)
```
  $ cd getGPS
  $ make SGX_PCL=1
  $ ./app
```

- 他のオプション等は公式リファレンスや linuc-sgx/SampleCode あたりを読んでください．


コードの挙動説明
-----------------

`$ make SGX_PCL=0` を実行したとする．その後必要なファイルは
- app               : 実行バイナリ
- enclave.signed.so : CPU特有の署名付きの共有オブジェクト
- newgps.dat        : GPS取得機から得たファイル（と仮定）
のみ．

一度目の `./app` で
1. enclave領域の作成
1. 保護するデータの初期化
1. 保護したデータの上書き（追加）
1. enclave領域の破棄  
を行う．<br>
各実行ごとに print も行っている（この print も ECALL）．<br>
この時点で encgps.dat が作成される．これは作成したCPUしかわからない鍵で暗号化されたバイナリであるので外部からは読めない．

二度目以降の`./app` で
1. enclave領域の作成
1. encgps.dat からの過去のログの読み出し
1. 保護したデータの上書き（追加）
1. enclave領域の破棄  
を行う．

-------------------------------------------------

メモ
-------------------------------------------------
- Intel SGXは第6世代（Skylakeアーキテクチャ）以降のCPUから対応．詳しくは[こちら](https://github.com/ayeks/SGX-hardware/blob/master/README.md)
- Sealはなんのためにあるのか
    - enclave.signed.so がリバースエンジニアリング可能であるので enclave.so の作成時に異なるEnclaveで作成した鍵 sealed_key.bin を用いて暗号化
    - `make` 後，必要なファイルに sealed_key.bin が追加
    - そのマシン自体で動かし続ける分には全く必要なさそう
- 一介のB4の作成物なので信用しないでください
