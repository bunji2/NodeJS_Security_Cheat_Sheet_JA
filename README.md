# NodeJS セキュリティチートシート

【原文】https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html

## はじめに

このチートシートは、安全な Node.js アプリケーションを開発するために開発者が取るべき行動を列挙しています。
各項目には、Node.js 環境に特化した簡単な説明と解決策があります。

## 背景

Node.js アプリケーションは増加の一途をたどっており、他のフレームワークやプログラミング言語と何ら変わりはありません。
Node.js アプリケーションは、あらゆる種類のウェブ・アプリケーションの脆弱性を抱えがちです。

## 目的

このチート・シートは、 Node.js アプリケーションの開発時に採用すべきベスト・プラクティスのリストを提供することを目的としています。

## 推奨事項

Node.js アプリケーションのセキュリティを強化するために、いくつかの推奨事項があります。
これらは次のように分類されます：

* アプリケーション・セキュリティ
* エラーと例外処理
* サーバ・セキュリティ
* プラットフォーム・セキュリティ

## アプリケーション・セキュリティ

### フラットなPromiseチェーンを使用する

非同期コールバック関数は、 Node.js の最も強力な機能の 1 つです。
しかし、コールバック関数のネストの階層が増えると問題になることがあります。
どのような多段の処理でも、10 階層以上のネストになるおそれがあります。
この問題は「破滅のピラミッド」または「コールバック地獄」と呼ばれます。
このようなコードでは、エラーや処理結果がコールバックの中で失われてしまいます。
`Promise` は、ネストしたピラミッドに入ることなく非同期コードを書く良い方法です。
`Promise` は、エラーや結果を次の `.then` 関数に渡すことで、非同期でありながらトップダウンの実行を提供します。

`Promise` のもう一つの利点は、`Promise` がエラーを処理する方法です。
`Promise` クラスでエラーが発生した場合、`.then` 関数をスキップして最初に見つかった `.catch` 関数を呼び出します。
このように、`Promise` はより確実にエラーを捕捉し、処理することができます。
原則として、（エミッターを除けば）すべての非同期コードは `Promise` を返すようにすることができます。
注意しなければならないのは、`Promise` の呼び出しはピラミッド型になる可能性があるということです。
「コールバック地獄」から完全に逃れるためには、フラットな `Promise` チェーンを使うべきです。
使用しているモジュールが `Promise` をサポートしていない場合は、`Promise.promisifyAll()` 関数を使用してベースオブジェクトを `Promise` に変換することができます。

次のコード・スニペットは「コールバック地獄」の例です：

```javascript
function func1(name, callback) {
  // operations that takes a bit of time and then calls the callback
}
function func2(name, callback) {
  // operations that takes a bit of time and then calls the callback
}
function func3(name, callback) {
  // operations that takes a bit of time and then calls the callback
}
function func4(name, callback) {
  // operations that takes a bit of time and then calls the callback
}

func1("input1", function(err, result1){
   if(err){
      // error operations
   }
   else {
      //some operations
      func2("input2", function(err, result2){
         if(err){
            //error operations
         }
         else{
            //some operations
            func3("input3", function(err, result3){
               if(err){
                  //error operations
               }
               else{
                  // some operations
                  func4("input 4", function(err, result4){
                     if(err){
                        // error operations
                     }
                     else {
                        // some operations
                     }
                  });
               }
            });
         }
      });
   }
});
```

上記のコードは、フラットな `Promise` チェーンを使って次のように安全に書くことができます：

```javascript
function func1(name) {
  // operations that takes a bit of time and then resolves the promise
}
function func2(name) {
  // operations that takes a bit of time and then resolves the promise
}
function func3(name) {
  // operations that takes a bit of time and then resolves the promise
}
function func4(name) {
  // operations that takes a bit of time and then resolves the promise
}

func1("input1")
   .then(function (result){
      return func2("input2");
   })
   .then(function (result){
      return func3("input3");
   })
   .then(function (result){
      return func4("input4");
   })
   .catch(function (error) {
      // error operations
   });
```

そして `async/await` を使うと次のように書くことができます：

```javascript
function async func1(name) {
  // operations that takes a bit of time and then resolves the promise
}
function async func2(name) {
  // operations that takes a bit of time and then resolves the promise
}
function async func3(name) {
  // operations that takes a bit of time and then resolves the promise
}
function async func4(name) {
  // operations that takes a bit of time and then resolves the promise
}

(async() => {
  try {
    let res1 = await func1("input1");
    let res2 = await func2("input2");
    let res3 = await func3("input2");
    let res4 = await func4("input2");
  } catch(err) {
    // error operations
  }
})();
```

### リクエストサイズ制限の設定

リクエストボディのバッファリングと解析はリソースを大量に消費します。
リクエストのサイズに制限がないと、攻撃者は大きなリクエストボディのリクエストを送ることができ、サーバのメモリを使い果たしたり、ディスク領域を 満たしたりすることができます。
`raw-body` を使うことで、すべてのリクエストのリクエストボディのサイズを制限することができます。

```javascript
const contentType = require('content-type')
const express = require('express')
const getRawBody = require('raw-body')

const app = express()

app.use(function (req, res, next) {
  if (!['POST', 'PUT', 'DELETE'].includes(req.method)) {
    next()
    return
  }

  getRawBody(req, {
    length: req.headers['content-length'],
    limit: '1kb',
    encoding: contentType.parse(req).parameters.charset
  }, function (err, string) {
    if (err) return next(err)
    req.text = string
    next()
  })
})
```

しかしながら、ファイルをアップロードするときなど、リクエストボディ に大きなペイロードを持つリクエストもあるかもしれず、すべてのリクエストにリクエストサイズの制限を固定することは正しい動作ではないかもしれません。
また、JSON タイプの入力は、JSON の解析がブロック操作なので、マルチパート入力よりも危険です。
したがって、コンテンツタイプごとにリクエストサイズの制限を設定する必要があります。
express ミドルウェアを使えば、以下のように非常に簡単に実現できます：

```javascript
app.use(express.urlencoded({ extended: true, limit: "1kb" }));
app.use(express.json({ limit: "1kb" }));
```

攻撃者はリクエストの Content-Type ヘッダーを変更し、リクエストのサイズ制限をバイパスできることに注意すべきでです。
したがって、リクエストを処理する前に、リクエストに含まれるデータをリクエストヘッダに記述されたコンテンツタイプに対して検証する必要があります。
各リクエストのコンテントタイプのバリデーションがパフォーマンスに重大な影響を与える場合、特定のコンテントタイプまたはあらかじめ決められたサイズ以上のリクエストだけをバリデーションすることができます。

### イベントループをブロックしない

Node.js は、スレッドを使用する一般的なアプリケーション・プラットフォームとは大きく異なります。
Node.js はシングルスレッド・イベント駆動アーキテクチャを採用しています。
このアーキテクチャにより、スループットが高くなり、プログラミングモデルがシンプルになります。
Node.js は、ノンブロッキング I/O イベントループを中心に実装されています。
このイベント・ループでは、I/O の待ち時間やコンテキストの切り替えはありません。
イベントループはイベントを探し、ハンドラ関数にディスパッチします。
このため、CPU に負荷のかかる JavaScript の処理が実行されると、イベントループは処理が終わるのを待ちます。
このため、このような処理は「ブロッキング」と呼ばれます。
この問題を克服するために、 Node.js では I/O ブロックされたイベントにコールバックを割り当てることができます。
こうすることで、メイン・アプリケーションはブロックされず、コールバックは非同期で実行されます。
したがって、一般的な原則としては、イベント・ループがブロックされないように、すべてのブロック操作は非同期で実行する必要があります。

非同期にブロッキング処理を実行しても、アプリケーションが期待通りに動作しないことがあります。
これは、コールバックの外側に、コールバック内のコードが最初に実行されることに依存しているコードがある場合に起こります。
例えば、以下のコードを考えてみましょう：

```javascript
const fs = require('fs');
fs.readFile('/file.txt', (err, data) => {
  // perform actions on file content
});
fs.unlinkSync('/file.txt');
```

上記の例では、`unlinkSync` 関数がコールバックより先に実行される可能性があり、ファイル・コンテンツに対する所望のアクションが実行される前にファイルが削除されてしまいます。
このような競合状態は、アプリケーションのセキュリティにも影響します。
例えば、認証がコールバックで実行され、認証されたアクションが同期的に実行されるようなシナリオです。
このような競合状態をなくすには、互いに依存し合うすべての処理を、単一のノンブロッキング関数に記述します。
そうすることで、すべての操作が正しい順序で実行されることが保証されます。
例えば、上記のコード例をノンブロッキングで書くと以下のようになります：

```javascript
const fs = require('fs');
fs.readFile('/file.txt', (err, data) => {
  // perform actions on file content
  fs.unlink('/file.txt', (err) => {
    if (err) throw err;
  });
});
```

上記のコードでは、ファイルの `unlink` する呼び出しと他のファイル操作は同じコールバック内にあります。
これにより、正しい操作順序が提供されます。

### 入力バリデーションの実施

入力バリデーションは、アプリケーション・セキュリティの重要な部分です。
入力バリデーションの失敗は、多くのタイプのアプリケーション攻撃を引き起こす可能性があります。
これには、SQL インジェクション、クロスサイト・スクリプティング、コマンド・インジェクション、ローカル/リモート・ファイル・インクルージョン、サービス拒否、ディレクトリ・トラバーサル、LDAP インジェクション、その他多くのインジェクション攻撃が含まれます。
これらの攻撃を避けるために、アプリケーションへの入力は最初にサニタイズされなければなりません。
最良の入力バリデーション技法は、受け入れられる入力のリストを使用することです。
しかし、それが不可能な場合、入力はまず期待される入力スキームと照合され、危険な入力はエスケープされなければなりません。
Node.js アプリケーションの入力検証を簡単にするために、[validator](https://www.npmjs.com/package/validator) や [express-mongo-sanitize](https://www.npmjs.com/package/express-mongo-sanitize) のようなモジュールがあります。
入力検証の詳細については、[入力検証チートシート](https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html)を参照してください。

JavaScript は動的な言語なので、フレームワークがどのように URL を解析するかによって、アプリケーションコードが参照するデータはさまざまな形になります。
以下は、`express.js` でクエリー文字列を解析した後の例です：

| URL | コード中の `request.query.foo` の中身 |
| :-- | :-- |
| ?foo=bar	| 'bar' (文字列) |
| ?foo=bar&foo=baz	| ['bar', 'baz'] (文字列の配列) |
| ?foo[]=bar	| ['bar'] (文字列の配列) |
| ?foo[]=bar&foo[]=baz	| ['bar', 'baz'] (文字列の配列) |
| ?foo[bar]=baz	| { bar : 'baz' } (キーを持ったオブジェクト) |
| ?foo[]baz=bar	| ['bar'] (文字列の配列。ポストフィックスは虫される) |
| ?foo[][baz]=bar	| [ { baz: 'bar' } ] (オブジェクトの配列) |
| ?foo[bar][baz]=bar	| { foo: { bar: { baz: 'bar' } } } (オブジェクトのツリー) |
| ?foo[10]=bar&foo[9]=baz	| [ 'baz', 'bar' ] (文字列の配列。順番に注目) |
| ?foo[toString]=bar	| {} (オブジェクト。`toString()` の呼び出しに失敗) |

### 出力エスケープの実行

入力バリデーションに加えて、クロスサイトスクリプティング（XSS）攻撃を防ぐために、アプリケーションを介してユーザーに表示されるすべての HTML と JavaScript コンテンツをエスケープする必要があります。
[escape-html](https://github.com/component/escape-html) や [node-esapi](https://github.com/ESAPI/node-esapi) ライブラリを使えば、出力エスケープを行うことができます。

### アプリケーション・アクティビティのロギングの実施

アプリケーション・アクティビティをログに記録することは、推奨されるグッドプラクティスです。
これは、アプリケーションの実行中に遭遇したエラーのデバッグを容易にします。
また、インシデントレスポンス中に使用することができるため、セキュ リティの観点からも有用です。
さらに、これらのログは、侵入検知/防止システム（IDS/IPS）に供給するために使用することができます。
Node.js には、`Winston`、`Bunyan`、`Pino` など、アプリケーション・アクティビティー・ロギングを実行するモジュールがあります。
これらのモジュールは、ログのストリーミングとクエリーを可能にし、捕捉されなかった例外を処理する方法を提供します。

以下のコードで、アプリケーションのアクティビティをコンソールと任意のログファイルの両方に記録できます：

```javascript
const logger = new (Winston.Logger) ({
    transports: [
        new (winston.transports.Console)(),
        new (winston.transports.File)({ filename: 'application.log' })
    ],
    level: 'verbose'
});
```

エラーを別のログファイルに保存し、一般的なアプリケーションログを別のログファイルに保存できるように、異なるトランスポートを提供することができます。
セキュリティ・ロギングに関して、[ロギング・チート・シート](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html) に追加情報があります。

### イベント・ループの監視

アプリケーションサーバにネットワークトラフィックが集中すると、ユーザにサービスを提供できなくなるおそれがあります。
これは本質的に[サービス拒否(DoS)攻撃](https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html)の一種です。
[toobusy-js](https://www.npmjs.com/package/toobusy-js) モジュールを使うと、イベントループを監視することができます。
応答時間を追跡し、それがある閾値を超えると、このモジュールはサーバーがビジー状態であることを示します。
その場合、入ってくるリクエストの処理を停止し、アプリケーションが応答し続けるように、503 Server Too Busy メッセージを送ることができます。
`toobusy-js` モジュールの使用例を示します：

```javascript
const toobusy = require('toobusy-js');
const express = require('express');
const app = express();
app.use(function(req, res, next) {
    if (toobusy()) {
        // log if you see necessary
        res.status(503).send("Server Too Busy");
    } else {
    next();
    }
});
```

### ブルート・フォースに対する予防策を講じる

ブルート・フォース攻撃は、すべてのウェブアプリケーションに共通する脅威です。
攻撃者はブルート・フォース攻撃をパスワード推測攻撃として利用し、アカウントのパスワードを入手することができます。
したがって、アプリケーション開発者は、特にログイン・ページにおいて、ブルート・フォース攻撃に対する予防策を講じる必要があります。
Node.js には、この目的のために利用可能なモジュールがいくつかあります。
[Express-bouncer](https://libraries.io/npm/express-bouncer)、[express-brute](https://libraries.io/npm/express-brute)、[rate-limiter](https://libraries.io/npm/rate-limiter) などがその一例です。
あなたのニーズと要件に基づいて、これらのモジュールの1つまたは複数を選択し、それに応じて使用する必要があります。
`express-bouncer` と `express-brute` モジュールは同じように動作します。
これらは失敗したリクエストの遅延を増加させ、特定のルートに配置できます。
これらのモジュールは以下のように使うことができます：

```javascript
const bouncer = require('express-bouncer');
bouncer.whitelist.push('127.0.0.1'); // allow an IP address
// give a custom error message
bouncer.blocked = function (req, res, next, remaining) {
    res.status(429).send("Too many requests have been made. Please wait " + remaining/1000 + " seconds.");
};
// route to protect
app.post("/login", bouncer.block, function(req, res) {
    if (LoginFailed){  }
    else {
        bouncer.reset( req );
    }
});
```

```javascript
const ExpressBrute = require('express-brute');

const store = new ExpressBrute.MemoryStore(); // stores state locally, don't use this in production
const bruteforce = new ExpressBrute(store);

app.post('/auth',
    bruteforce.prevent, // error 429 if we hit this route too often
    function (req, res, next) {
        res.send('Success!');
    }
);
```

（ステータスコード 429 はユーザが一定時間内に送信したリクエスト数が多すぎることを示す。）


`express-bouncer` と `express-brute` とは別に、`rate-limiter` モジュールもブルート・フォース攻撃を防ぐのに役立ちます。
こちらは、特定の IP アドレスが指定された期間にどれだけのリクエストを行えるかを指定することができます。

```javascript
const limiter = new RateLimiter();
limiter.addLimit('/login', 'GET', 5, 500); // login page can be requested 5 times at max within 500 seconds
```

CAPTCHA の使用も、ブルート・フォースに対してよく使われるメカニズムです。
Node.js CAPTCHA 用に開発されたモジュールがあります。
Node.js アプリケーションでよく使われるモジュールは `svg-captcha` です。
以下のように使用できます：

```javascript
const svgCaptcha = require('svg-captcha');
app.get('/captcha', function (req, res) {
    const captcha = svgCaptcha.create();
    req.session.captcha = captcha.text;
    res.type('svg');
    res.status(200).send(captcha.data);
});
```

[アカウントロックアウト](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html#account-lockout)は、有効なユーザから攻撃者を遠ざけるために推奨されるソリューションです。
アカウントロックアウトは [mongoose](https://www.npmjs.com/package/mongoose) のような多くのモジュールで可能です。
`mongoose` でどのようにアカウントロックアウトが実装されているかは、[こちらのブログの記事](http://devsmash.com/blog/implementing-max-login-attempts-with-mongoose) を参照してください。

### アンチ CSRF トークンを使用する

[クロスサイト・リクエスト・フォージェリ(CSRF)](https://owasp.org/www-community/attacks/csrf) は、認証されたユーザに代わって認証されたアクションを本人の知らぬ間に実行することを目的としています。
CSRF 攻撃は一般的に、パスワードの変更、ユーザーの追加、注文など、状態を変更するリクエストに対して行われます。
`Csurf` は、CSRF 攻撃を軽減するために使用されてきた Express ミドルウェアです。
しかし、このパッケージのセキュリティホールが最近発見されました。
このパッケージの開発チームは発見された脆弱性を修正しておらず、このパッケージを非推奨とし、他の CSRF 保護パッケージを使用することを推奨しています。

クロスサイトリクエストフォージェリ(CSRF)攻撃とその防御方法についての詳しい情報は、[クロスサイトリクエストフォージェリ防御](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html) を参照してください。

### 不必要な経路の削除

ウェブ・アプリケーションは、ユーザが使用しないページを含むべきではありません。
したがって、Node.js アプリケーションでは、使用されない API ルートはすべて無効にする必要があります。
特に [Sails](https://sailsjs.com/) や [Feathers](https://feathersjs.com/) のようなフレームワークでは、REST API エンドポイントが自動的に生成されるため、このような現象が発生します。
例えば、`Sails` では、URL がカスタムルートにマッチしない場合、自動ルートの1つにマッチし、それでもレスポンスが生成されることがあります。
このような状況は、情報漏えいから任意のコマンドの実行に至るまで、さまざまな結果につながる可能性があります。
したがって、このようなフレームワークやモジュールを使う前に、それらが自動的に生成するルートを知り、これらのルートを削除するか無効にすることが重要です。

### HTTPパラメータ汚染を防ぐ

HTTP Parameter Pollution（HPP）とは、攻撃者が同じ名前の HTTP パラメータを複数送信することで、アプリケーションがそれらを予測不可能に解釈してしまう攻撃です。
複数のパラメータ値が送信されると、Express はそれらを配列に格納します。
この問題を解決するには、`hpp` モジュールを使用します。
このモジュールを使用すると、`req.query` や `req.body` でパラメータとして送信されたすべての値を無視し、最後に送信されたパラメータ値だけを選択します。
使い方は以下の通りです：

```javascript
const hpp = require('hpp');
app.use(hpp());
```

### 必要なものだけを返す

アプリケーションのユーザに関する情報は、アプリケーションに関する最も重要な情報の一つです。
ユーザテーブルには一般に、id、ユーザ名、フルネーム、電子メールアドレス、生年月日、パスワード、場合によっては社会保障番号などのフィールドが含まれます。
従って、ユーザオブジェクトをクエリして使用する場合、個人情報漏洩の危険性があるため、必要なフィールドのみを返す 必要があります。
これは、データベースに保存されている他のオブジェクトについても同様です。
オブジェクトの特定のフィールドだけが必要な場合は、必要な特定のフィールドだけを返すようにします。
例として、あるユーザーに関する情報を取得する必要がある場合、次のような関数を使用することができます。
そうすることで、特定の操作に必要なフィールドだけを返すことができます。
言い換えると、利用可能なユーザーの名前だけをリストアップする必要がある場合、フルネームに加えてメールアドレスやクレジットカード番号を返すことはありません。

```javascript
exports.sanitizeUser = function(user) {
  return {
    id: user.id,
    username: user.username,
    fullName: user.fullName
  };
};
```

### オブジェクト・プロパティ記述子を使う

オブジェクト・プロパティには 3 つの隠し属性があります： 書き込み可能（`false` の場合、プロパティの値は変更できません）、列挙可能（`false` の場合、プロパティは `for` ループで使用できません）、設定可能（`false` の場合、プロパティは削除できません）。
代入によってオブジェクト・プロパティを定義する場合、これら 3 つの隠し属性はデフォルトで `true` に設定されます。
これらのプロパティは以下のように設定できます：

```javascript
const o = {};
Object.defineProperty(o, "a", {
    writable: true,
    enumerable: true,
    configurable: true,
    value: "A"
});
```

これらとは別に、オブジェクトの属性に関する特別な関数がいくつかあります。
`Object.preventExtensions()` は、オブジェクトに新しいプロパティが追加されるのを防ぎます。

### アクセスコントロールリストの使用

権限付与は、ユーザが意図した権限外で行動することを防ぎます。
そのためには、最小特権の原則を考慮してユーザーとその役割を決定する必要があります。
各ユーザ・ロールは、使用しなければならないリソースにのみアクセスできるようにします。
Node.js アプリケーションでは、ACL（アクセス制御リスト）の実装を提供する [acl](https://www.npmjs.com/package/acl) モジュールを使用できます。
このモジュールを使って、ロールを作成し、そのロールにユーザーを割り当てることができます。

## エラーと例外処理

### uncaughtException の処理

Node.js の未捕捉な例外の動作は、現在のスタック・トレースを表示し、スレッドを終了することです。
しかし、Node.js はこの動作をカスタマイズすることができます。
すべての Node.js アプリケーションで利用可能な `process` という名前のグローバル・オブジェクトを提供します。
これは `EventEmitter` オブジェクトで、捕捉されない例外が発生した場合、`uncaughtException` イベントが発行され、メイン・イベント・ループに持ち込まれます。
捕捉されなかった例外に対するカスタム動作を提供するために、このイベントにバインドすることができます。
しかし、このような捕捉されない例外が発生した後にアプリケーションを再開すると、さらに問題が発生する可能性があります。
したがって、捕捉されなかった例外を逃したくない場合は、`uncaughtException` イベントにバインドし、プロセスをシャットダウンする前にファイル記述子やハンドルなどの割り当てられたリソースをクリーンアップする必要があります。
アプリケーションを再開することは、アプリケーションが未知の状態になるため、強くお勧めしません。
捕捉されない例外が発生した場合にエラー・メッセージを表示する際、スタック・トレースのような詳細情報をユーザーに表示すべきではないことに注意することが重要です。
その代わりに、情報漏洩を起こさないようにするため、カスタム・エラー・メッセージをユーザーに表示する必要があります。

```javascript
process.on("uncaughtException", function(err) {
    // clean up allocated resources
    // log necessary error details to log files
    process.exit(); // exit the process to avoid unknown state
});
```

### EventEmitter使用時のエラーを聞く

`EventEmitter` を使用する場合、エラーはイベント・チェーンのどこででも発生します。
通常、`EventEmitter` オブジェクトでエラーが発生すると、引数としてエラー・オブジェクトを持つエラー・イベントが呼び出されます。
しかし、そのエラー・イベントのリスナーがアタッチされていない場合、引数として送られたエラー・オブジェクトはスローされ、キャッチされない例外となります。
つまり、`EventEmitter` オブジェクト内のエラーを適切に処理しないと、処理されないエラーがアプリケーションをクラッシュさせる可能性があります。
したがって、`EventEmitter` オブジェクトを使用する場合は、常にエラー・イベントをリッスンする必要があります。

### 非同期呼び出しのエラー処理

非同期コールバック内で発生するエラーは見逃しやすいです。
したがって、一般的な原則として、非同期呼び出しの最初の引数はエラー・オブジェクトでなければなりません。
また、`Express routes` はエラーそのものを処理しますが、`Express routes` 内の非同期呼び出しで発生したエラーは、第一引数にエラー・オブジェクトが送られない限り処理されないことを常に覚えておく必要があります。

これらのコールバックでのエラーは、可能な限り何度でも伝播させることができます。
エラーが伝播された各コールバックは、エラーを無視、処理、または伝播することができます。

## サーバーのセキュリティ

### クッキーのフラグを適切に設定する

一般にウェブ・アプリケーションでは、セッション情報はクッキーを使って送信されます。
しかし HTTP クッキーの不適切な使用は、アプリケーションをいくつかのセッション管理の脆弱性にさらす可能性があります。
httpOnly フラグ、Secure フラグ、SameSite フラグはセッション・クッキーにとって非常に重要です。
これは XSS 攻撃に対する効果的な対策です。
Secure フラグは、通信が HTTPS 経由である場合にのみクッキーを送信します。
SameSite フラグは、クロスサイトリクエストでクッキーが送信されるのを防ぐことができ、クロスサイトリクエストフォージェリ (CSRF)攻撃からの保護に役立ちます。
これらとは別に、domain、path、expires のようなフラグがあります。
これらのフラグを適切に設定することが推奨されますが、それらはほとんどクッキーのセキュリティではなく、クッキーのスコープに関係します。
これらのフラグの使用例を次の例に示します：

```javascript
const session = require('express-session');
app.use(session({
    secret: 'your-secret-key',
    name: 'cookieName',
    cookie: { secure: true, httpOnly: true, path: '/user', sameSite: true}
}));
```

### 適切なセキュリティ・ヘッダを使う

一般的な攻撃ベクトルを防ぐのに役立つHTTPセキュリティヘッダがいくつかあります。
[helmet](https://www.npmjs.com/package/helmet) パッケージはこれらのヘッダを設定するのに役立ちます：

```javascript
const express = require("express");
const helmet = require("helmet");

const app = express();

app.use(helmet()); // Add various HTTP headers
```

トップレベルの `helmet` 関数は、14 の小さなミドルウェアのラッパーであります。
以下は、`helmet` ミドルウェアがカバーする HTTP セキュリティヘッダのリストです：

* [Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security): [HTTP Strict Transport Security (HSTS)](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) は、アプリケーションが HTTPS 接続経由でのみアクセスできることをブラウザに指示します。
アプリケーションで使用するには、以下のコードを追加してください：

```javascript
app.use(helmet.hsts()); // default configuration
app.use(
  helmet.hsts({
    maxAge: 123456,
    includeSubDomains: false,
  })
); // custom configuration
```

* [X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options): &lt;frame&gt; 要素または &lt;iframe&gt; 要素を介してページを読み込むことができるかどうかを決定します。
ページのフレーム化を許可すると、[クリックジャッキング攻撃](https://owasp.org/www-community/attacks/Clickjacking) を受ける可能性があります。

```javascript
app.use(helmet.frameguard()); // default behavior (SAMEORIGIN)
```

* [X-XSS-Protection](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection)：クロスサイト・スクリプティング（XSS）攻撃を検知した場合、ページの読み込みを停止します。
このヘッダは最近のブラウザでは非推奨となっており、このヘッダを使用するとクライアント側でさらにセキュリティ上の問題が発生する可能性があります。
そのため、ヘッダを `X-XSS-Protection: 0` に設定することを推奨します。これは、XSS Auditor を無効にし、レスポンスを処理するブラウザのデフォルトの動作を許可しないようにするためです。

```javascript
app.use(helmet.xssFilter()); // sets "X-XSS-Protection: 0"
```

最近のブラウザでは、次のセクションで詳しく説明するように、強力な Content-Security-Policy ポリシーを実装することが推奨されています。

* [Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy): コンテンツ・セキュリティ・ポリシーは、[クロスサイト・スクリプティング（XSS）](https://owasp.org/www-community/attacks/xss/) や[クリックジャッキング](https://owasp.org/www-community/attacks/Clickjacking) のような攻撃のリスクを減らすために開発されました。
あなたが決めたリストからコンテンツを許可します。
いくつかのディレクティブがあり、それぞれ特定の種類のコンテンツの読み込みを禁止します。
各ディレクティブの詳細な説明と使用方法については、[Content Security Policy Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html) を参照してください。
これらの設定をアプリケーションに実装するには、以下のようにします：

```javascript
app.use(
  helmet.contentSecurityPolicy({
    // the following directives will be merged into the default helmet CSP policy
    directives: {
      defaultSrc: ["'self'"],  // default value for all directives that are absent
      scriptSrc: ["'self'"],   // helps prevent XSS attacks
      frameAncestors: ["'none'"],  // helps prevent Clickjacking attacks
      imgSrc: ["'self'", "'http://imgexample.com'"],
      styleSrc: ["'none'"]
    }
  })
);
```

このミドルウェアはほとんど検証を行わないため、代わりに [CSP Evaluator](https://csp-evaluator.withgoogle.com/) のような CSP チェッカを信頼することが推奨されます。

* [X-Content-Type-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options)： サーバがレスポンスに有効な Content-Type ヘッダを設定しても、ブラウザは要求されたリソースの MIME タイプを推測しようとすることがあります。
このヘッダーはこの動作を止め、Content-Type ヘッダーで指定された MIMEタイプを変更しないようにブラウザに伝える方法です。
このヘッダーは以下のように設定できます：

```javascript
app.use(helmet.noSniff());
```

* [Cache-Control](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control) と [Pragma](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma)： Cache-Control ヘッダはブラウザが与えられた応答をキャッシュしないようにするために使うことができます。
これは、ユーザやアプリケーションに関する機密情報を含むページに対して行われるべきです。
しかしながら、機密情報を含まないページのキャッシュを無効にすることは、アプリケーションのパフォーマンスに深刻な影響を与えるかもしれません。
したがって、機密情報を返すページに対してのみキャッシュを無効にすべきです。
適切なキャッシュ制御とヘッダーは、[nocacheパッケージ](https://www.npmjs.com/package/nocache) を使って簡単に設定できます：

```javascript
const nocache = require("nocache");

app.use(nocache());
```

上記のコードでは、Cache-Control、Surrogate-Control、Pragma、Expires ヘッダを適宜設定しています。

* X-Download-Options： このヘッダーは、Internet Explorer がダウンロードしたファイルをサイトのコンテキストで実行しないようにします。
これは noopen ディレクティブで実現できます。
以下のコードで実現できます：

```javascript
app.use(helmet.ieNoOpen());
```

* [Expect-CT](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT): 証明書の透明性は、現在の SSL インフラストラクチャの構造的な問題を解決するために開発された新しいメカニズムです。
Expect-CT ヘッダーは証明書の透明性要件を強制することができます。
これは以下のようにアプリケーションに実装することができます：

```javascript
const expectCt = require('expect-ct');
app.use(expectCt({ maxAge: 123 }));
app.use(expectCt({ enforce: true, maxAge: 123 }));
app.use(expectCt({ enforce: true, maxAge: 123, reportUri: 'http://example.com'}));
```

* X-Powered-By： X-Powered-By ヘッダーは、サーバー側でどのような技術が使用されているかを通知するために使用されます。
これは情報漏洩の原因となる不要なヘッダーなので、アプリケーションから削除する必要があります。
そのためには、以下のように `hidePoweredBy` を使用します：

```javascript
app.use(helmet.hidePoweredBy());
```

また、このヘッダで使用されている技術を偽ることもできます。
例えば、アプリケーションがPHPを使っていなくても、X-Powered-By ヘッダをそう見えるように設定することができます。

```javascript
app.use(helmet.hidePoweredBy({ setTo: 'PHP 4.2.0' }))；
```

## プラットフォームのセキュリティ

### パッケージを常に最新の状態に保つ

アプリケーションのセキュリティは、アプリケーションで使用するサードパーティパッケージの安全性に直接依存します。
したがって、パッケージを最新に保つことが重要です。
[既知の脆弱性を持つコンポーネントの使用](https://owasp.org/www-project-top-ten/OWASP_Top_Ten_2017/Top_10-2017_A9-Using_Components_with_Known_Vulnerabilities)は、OWASP Top 10 にまだ入っていることに注意すべきです。
[OWASP Dependency-Check](https://jeremylong.github.io/DependencyCheck/analyzers/nodejs.html) を使って、プロジェクトで使われているパッケージに既知の脆弱性があるかどうかを確認することができます。
また、[Retire.js](https://github.com/retirejs/retire.js/) を使って、既知の脆弱性を持つ JavaScript ライブラリをチェックすることもできます。

バージョン 6 から、npm は脆弱性のあるパッケージについて警告する audit を導入しました：

```
npm audit
```

npm はまた、影響を受けるパッケージをアップグレードする簡単な方法を提供します：

```
npm audit fix
```

依存関係をチェックするために使用できるツールは、他にもいくつかあります。
より包括的なリストは [Vulnerable Dependency Management CS](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html#tools) を参照下さい。

### 危険な関数を使わない

JavaScript の関数の中には危険なものがあり、必要な場合かやむを得ない場合にのみ使うべきです。
最初の例は `eval()` 関数です。
この関数は文字列を引数に取り、他の JavaScript ソースコードと同じように実行します。
ユーザー入力と組み合わせると、この動作は本質的にリモート・コード実行の脆弱性につながります。
同様に、`child_process.exec` の呼び出しも非常に危険です。
この関数は `bash` インタプリタとして動作し、引数を `/bin/sh` に送ります。
この関数に入力を注入することで、攻撃者はサーバー上で任意のコマンドを実行することができます。

これらの関数に加えて、使用時に特別な注意が必要なモジュールもあります。
例として、`fs` モジュールはファイルシステム操作を処理します。
しかし、不適切にサニタイズされたユーザ入力がこのモジュールに入力されると、アプリケーションはファイルインクルードやディレクトリトラバーサルの脆弱性を受ける可能性があります。
同様に、`vm` モジュールは V8 仮想マシンのコンテキスト内でコードをコンパイルし実行するための API を提供します。
このモジュールはもともと危険な動作をする可能性があるため、サンドボックス内で使用する必要があります。

これらの関数やモジュールを一切使ってはいけないと言うのは公平ではありませんが、特にユーザー入力を使う場合は慎重に使うべきです。
また、アプリケーションを脆弱にする可能性のある関数もいくつかあります。

### 邪悪な正規表現を避ける

正規表現サービス拒否攻撃（ReDoS）は、ほとんどの正規表現実装が、動作が非常に遅くなる（入力サイズに指数関数的に関係する）極端な状況に達する可能性があるという事実を悪用したものです。
攻撃者は、正規表現を使用するプログラムがこのような極端な状況に陥り、非常に長い時間ハングするように仕向けることができます。

[正規表現サービス拒否（ReDoS）](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS) は、正規表現を使ったサービス拒否攻撃の一種です。
正規表現(Regex)の実装の中には、アプリケーションが非常に遅くなるような極端な状況を引き起こすものがあります。
攻撃者は、このような正規表現の実装を使用して、アプリケーションをこのような極端な状況に陥らせ、長時間ハングアップさせることができます。
このような正規表現は、アプリケーションが細工された入力でスタックする可能性がある場合、悪と呼ばれます。
一般的に、これらの正規表現は繰り返しによるグループ化と重複による交替によって悪用されます。
例えば、次の正規表現 `^(([a-z])+.)+[A-Z]([a-z])+$` は、Java のクラス名を指定するために使用できます。
しかし、非常に長い文字列 (`aaaa...aaaaAaaa...aaaa`) もこの正規表現とマッチする可能性があります。
正規表現がサービス拒否を引き起こす可能性があるかどうかをチェックするツールがいくつかあります。
その一例が [vuln-regex-detector](https://github.com/davisjam/vuln-regex-detector) であります。

### セキュリティ・リンターの実行

コードを開発するとき、すべてのセキュリティのヒントを心に留めておくことは本当に難しいことです。
また、すべてのチーム・メンバーをこれらのルールに従わせ続けることは、ほとんど不可能です。
そのため、静的解析セキュリティテスト（SAST）ツールがあるのです。
これらのツールは、あなたのコードを実行するのではなく、単にセキュリティリスクを含む可能性のあるパターンを探します。
JavaScript は動的で疎な型付けの言語なので、リントツールはソフトウェア開発のライフサイクルにおいて本当に不可欠です。
リンティング・ルールは定期的にレビューされ、発見された内容は監査されるべきです。
これらのツールのもう一つの利点は、危険と思われるパターンに対してカスタムルールを追加できることです。
[ESLint](https://eslint.org/) と [JSHintはJavaScript](https://eslint.org/) のリンティングによく使われる SAST ツールです。

### ストリクト・モードの使用

JavaScript には、使ってはいけない安全で危険なレガシー機能が数多くあります。
これらの機能を取り除くために、ES5 には開発者向けのストリクト・モードが含まれています。
このモードでは、以前はサイレントだったエラーがスローされます。
また、JavaScript エンジンの最適化にも役立ちます。
ストリクト・モードでは、以前は許容されていた間違った構文が実際のエラーになります。
これらの改善により、アプリケーションでは常にストリクト・モードを使用する必要があります。
ストリクトモードを有効にするには、コードのトップで `"use strict";` と書くだけです。

以下のコードはコンソールに `"ReferenceError: Can't find variable: y"` を表示するが、これはストリクト・モードを使用しない限り表示されない：

```javascript
"use strict";

func();
function func() {
  y = 3.14;   // This will cause an error (y is not defined)
}
```

### 一般的なアプリケーション・セキュリティの原則に従うこと

このリストは、主に Node.js アプリケーションで一般的な問題に焦点を当て、推奨事項と例を示しています。
これらに加えて、アプリケーション・サーバで使用される技術に関係なく、ウェブ・アプリケーションに適用される、[セキュリティ・バイ・デザイン原則](https://wiki.owasp.org/index.php/Security_by_Design_Principles) があります。
また、アプリケーションを開発する間、これらの原則を心に留めておく必要があります。
[OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/) を参照することで、ウェブアプリケーションの脆弱性と、それに対して使用される緩和技法につ いて、より詳しく知ることができます。

## Node.js のセキュリティに関するその他のリソース

[Awesome Node.js Security resources](https://github.com/lirantal/awesome-nodejs-security)

```
Additional resources about Node.js security
Awesome Node.js Security resources
```
