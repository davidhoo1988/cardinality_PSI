// @file math.cpp - Example of basic modular arithmetic
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// This is a main() file built to test math  operations
// D. Cousins

#define PROFILE  // need to define in order to turn on timing reporting

#include <chrono>
#include <exception>
#include <fstream>
#include <iostream>
#include "palisadecore.h"
#include "time.h"

using namespace std;
using namespace lbcrypto;

// define the main sections of the test

void test_BigVector(usint nloop);  // test old version of big int vector

// main()   need this for Kurts' makefile to ignore this.
int main(int argc, char *argv[]) {
  usint nloop = 10;
  if (argc > 1) nloop = atoi(argv[1]);

  if (nloop < 1) nloop = 1;
  cout << "running " << argv[0] << " nloop = " << nloop << endl;

  test_BigVector(nloop);
  return 0;
}

// Testing macro runs the desired code
// res = fn
// an a loop nloop times, timed with timer t with res compared to testval

#define TESTIT(t, res, fn, testval, nloop)                                \
  do {                                                                    \
    try {                                                                 \
      TIC(t);                                                             \
      for (usint j = 0; j < nloop; j++) {                                 \
        res = (fn);                                                       \
      }                                                                   \
      time2 = TOC(t);                                                     \
      PROFILELOG(#t << ": " << nloop << " loops " << #res << " = " << #fn \
                    << " computation time: "                              \
                    << "\t" << time2 << " us");                           \
      if (res != testval) {                                               \
        cout << "Bad " << #res << " = " << #fn << endl;                   \
        /*vec_diff(res, testval);*/                                       \
      }                                                                   \
    } catch (exception & e) {                                             \
      cout << #res << " = " << #fn << " caught exception " << e.what()    \
           << endl;                                                       \
    }                                                                     \
  } while (0);

// helper function that bulds BigVector from a vector of strings
BigVector BBVfromStrvec(std::vector<std::string> &s) {
  BigVector a(s.size());
  for (usint i = 0; i < s.size(); i++) {
    a.at(i) = s[i];
  }
  return a;
}

// function to compare two BigVectors and print differing indicies
void vec_diff(BigVector &a, BigVector &b) {
  for (usint i = 0; i < a.GetLength(); ++i) {
    if (a.at(i) != b.at(i)) {
      cout << "i: " << i << endl;
      cout << "first vector " << endl;
      cout << a.at(i);
      cout << endl;
      cout << "second vector " << endl;
      cout << b.at(i);
      cout << endl;
    }
  }
}

// main BigVector test suite. tests math
void test_BigVector(usint nloop) {
  cout << "testing BigVector" << endl;

  TimeVar t1, t2, t3;  // timers for TIC() TOC()
  double time2;

  // there are three test cases, 1) small modulus 2)approx 48 bits. 3)
  // very big numbers

  // note this fails BigInteger q1 = {"00000000000000163841"};
  BigInteger q1("00000000000000163841");

  // for each vector, define a, b inputs as vectors of strings
  std::vector<std::string> a1strvec = {
      "00000000000000127753", "00000000000000077706", "00000000000000017133",
      "00000000000000022582", "00000000000000112132", "00000000000000027625",
      "00000000000000126773", "00000000000000008924", "00000000000000125972",
      "00000000000000002551", "00000000000000113837", "00000000000000112045",
      "00000000000000100953", "00000000000000077352", "00000000000000132013",
      "00000000000000057029",
  };

  // this fails too!!! BigVector a1(a1string);
  // so I wrote this function
  BigVector a1 = BBVfromStrvec(a1strvec);
  a1.SetModulus(q1);

  // b:
  std::vector<std::string> b1strvec = {
      "00000000000000066773", "00000000000000069572", "00000000000000142134",
      "00000000000000141115", "00000000000000123182", "00000000000000155822",
      "00000000000000128147", "00000000000000094818", "00000000000000135782",
      "00000000000000030844", "00000000000000088634", "00000000000000099407",
      "00000000000000053647", "00000000000000111689", "00000000000000028502",
      "00000000000000026401",
  };

  BigVector b1 = BBVfromStrvec(b1strvec);
  b1.SetModulus(q1);

  // now test all mod functions Note BigVector implies modulus ALWAYS

  // load correct values of math functions of a and b
  // modadd:
  std::vector<std::string> modsum1strvec = {
      "00000000000000030685", "00000000000000147278", "00000000000000159267",
      "00000000000000163697", "00000000000000071473", "00000000000000019606",
      "00000000000000091079", "00000000000000103742", "00000000000000097913",
      "00000000000000033395", "00000000000000038630", "00000000000000047611",
      "00000000000000154600", "00000000000000025200", "00000000000000160515",
      "00000000000000083430",
  };
  BigVector modsum1 = BBVfromStrvec(modsum1strvec);
  modsum1.SetModulus(q1);

  // modsub:
  std::vector<std::string> moddiff1strvec = {
      "00000000000000060980", "00000000000000008134", "00000000000000038840",
      "00000000000000045308", "00000000000000152791", "00000000000000035644",
      "00000000000000162467", "00000000000000077947", "00000000000000154031",
      "00000000000000135548", "00000000000000025203", "00000000000000012638",
      "00000000000000047306", "00000000000000129504", "00000000000000103511",
      "00000000000000030628",
  };
  BigVector moddiff1 = BBVfromStrvec(moddiff1strvec);
  moddiff1.SetModulus(q1);
  // modmul:

  std::vector<std::string> modmul1strvec = {
      "00000000000000069404", "00000000000000064196", "00000000000000013039",
      "00000000000000115321", "00000000000000028519", "00000000000000151998",
      "00000000000000089117", "00000000000000080908", "00000000000000057386",
      "00000000000000039364", "00000000000000008355", "00000000000000146135",
      "00000000000000061336", "00000000000000031598", "00000000000000025961",
      "00000000000000087680",
  };

  BigVector modmul1 = BBVfromStrvec(modmul1strvec);
  modmul1.SetModulus(q1);

  BigVector c1, c2, c3;  // result vectors

  // compute results for each function and compare.

#if 1
  TESTIT(t1, c1, a1 + b1, modsum1, nloop);
  TESTIT(t1, c1, a1.ModAdd(b1), modsum1, nloop);
  TESTIT(t1, c1, a1 - b1, moddiff1, nloop);
  TESTIT(t1, c1, a1.ModSub(b1), moddiff1, nloop);
  TESTIT(t1, c1, a1 * b1, modmul1, nloop);
  TESTIT(t1, c1, a1.ModMul(b1), modmul1, nloop);
#endif
  // test case 2
  BigInteger q2("00004057816419532801");

  std::vector<std::string> a2strvec = {
      "00000185225172798255", "00000098879665709163", "00003497410031351258",
      "00004012431933509255", "00001543020758028581", "00000135094568432141",
      "00003976954337141739", "00004030348521557120", "00000175940803531155",
      "00000435236277692967", "00003304652649070144", "00002032520019613814",
      "00000375749152798379", "00003933203511673255", "00002293434116159938",
      "00001201413067178193",
  };

  BigVector a2 = BBVfromStrvec(a2strvec);
  a2.SetModulus(q2);

  std::vector<std::string> b2strvec = {
      "00000698898215124963", "00000039832572186149", "00001835473200214782",
      "00001041547470449968", "00001076152419903743", "00000433588874877196",
      "00002336100673132075", "00002990190360138614", "00000754647536064726",
      "00000702097990733190", "00002102063768035483", "00000119786389165930",
      "00003976652902630043", "00003238750424196678", "00002978742255253796",
      "00002124827461185795",
  };

  BigVector b2 = BBVfromStrvec(b2strvec);
  b2.SetModulus(q2);

  std::vector<std::string> modsum2strvec = {
      "00000884123387923218", "00000138712237895312", "00001275066812033239",
      "00000996162984426422", "00002619173177932324", "00000568683443309337",
      "00002255238590741013", "00002962722462162933", "00000930588339595881",
      "00001137334268426157", "00001348899997572826", "00002152306408779744",
      "00000294585635895621", "00003114137516337132", "00001214359951880933",
      "00003326240528363988",
  };
  BigVector modsum2 = BBVfromStrvec(modsum2strvec);
  modsum2.SetModulus(q2);

  std::vector<std::string> moddiff2strvec = {
      "00003544143377206093", "00000059047093523014", "00001661936831136476",
      "00002970884463059287", "00000466868338124838", "00003759322113087746",
      "00001640853664009664", "00001040158161418506", "00003479109686999230",
      "00003790954706492578", "00001202588881034661", "00001912733630447884",
      "00000456912669701137", "00000694453087476577", "00003372508280438943",
      "00003134402025525199",
  };
  BigVector moddiff2 = BBVfromStrvec(moddiff2strvec);
  moddiff2.SetModulus(q2);

  std::vector<std::string> modmul2strvec = {
      "00000585473140075497", "00003637571624495703", "00001216097920193708",
      "00001363577444007558", "00000694070384788800", "00002378590980295187",
      "00000903406520872185", "00000559510929662332", "00000322863634303789",
      "00001685429502680940", "00001715852907773825", "00002521152917532260",
      "00000781959737898673", "00002334258943108700", "00002573793300043944",
      "00001273980645866111",
  };

  BigVector modmul2 = BBVfromStrvec(modmul2strvec);
  modmul2.SetModulus(q2);
#if 1
  TESTIT(t2, c2, a2 + b2, modsum2, nloop);
  TESTIT(t2, c2, a2.ModAdd(b2), modsum2, nloop);
  TESTIT(t2, c2, a2 - b2, moddiff2, nloop);
  TESTIT(t2, c2, a2.ModSub(b2), moddiff2, nloop);
  TESTIT(t2, c2, a2 * b2, modmul2, nloop);
  TESTIT(t2, c2, a2.ModMul(b2), modmul2, nloop);
#endif

  // test case 3

  // q3: very large numbers.
  BigInteger q3(
      "327339060789614187001318969682759915221664204604306478948329136809613379"
      "640467455488327009232590415715088668412756007100921725654588539305332852"
      "7589431");

  std::vector<std::string> a3strvec = {
      "225900248779616490466577212189407858454340174415515429831272620924775168"
      "917218925565386635596420076848457541897386430736475723794694073374744664"
      "3725054",
      "147874381630800973466899287363338011091215980339799901595521201997125323"
      "152858946678960307474601044419913242155559832908255705398624026507153764"
      "7362089",
      "244225076656133434116682278367439513399555649531231801643114134874948273"
      "974978817417308131292727488014632998036342497756563800105684124567866178"
      "2610982",
      "917779106114096279364098211126816308037915672568153320523308800097705587"
      "686270523428976942621563981845568821206569141624247183330715577260930218"
      "556767",
      "214744931049447103852875386182628152420432967632133352449560778740158135"
      "437968557572597545037670326240142368149137864407874100658923913041236510"
      "842284",
      "302293102452655424148384130069043208311291201187071201820955225306834759"
      "262804310166292626381040137853241665577373849968102627833547035505519224"
      "0903881",
      "217787945810785525769991433173714489627467626905506243282655280886934812"
      "540767119958256354369228711471264229948214495931683561442667304898763469"
      "9368975",
      "297233451802123294436846683552230198845414118375785255038220841170372509"
      "047202030175469239142902723134737621108313142071558385068315554041062888"
      "072990"};

  BigVector a3 = BBVfromStrvec(a3strvec);
  a3.SetModulus(q3);

  std::vector<std::string> b3strvec = {
      "174640495219258626838115152142237214318214552597783670042038223724040064"
      "288925129795441832567518442778934843362636945066989255720843940121510948"
      "9355089",
      "220598825371098531288665964851212313477741334812037568788443848101743931"
      "352326362481681721872150902208420539619641973896119680592696228972313317"
      "042316",
      "163640803586734778369958874046918235045216548674527720352542780797135206"
      "316962206648897722950642085601703148269143908928802026200674823395417766"
      "9740311",
      "139186068174349558644651864688393305168565871835272263369428575847412480"
      "384747334906466055561884795171951026382969929229711913192643604521436425"
      "2430665",
      "840450278810654165061961485691366961514650606247291814263792869596294713"
      "810125269780258316551932763106025157596216051681623225968811609560121609"
      "943365",
      "232973186215009491235578658370287843476643614073859427486789149471300253"
      "408565273192088889150752235586797479161968667357492813737646810383958692"
      "1126803",
      "305947231662739654827190605151766588770023419265248863943743125469728517"
      "048418945877016815280052070202031309123443780623620419652619345575011736"
      "3744648",
      "132216870748476988853044482759545262615616157934129470128771906579101230"
      "690441206392939162889560305016204867157725209170345968349185675785497832"
      "527174"};

  BigVector b3 = BBVfromStrvec(b3strvec);
  b3.SetModulus(q3);

  std::vector<std::string> modsum3strvec = {
      "732016832092609303033733946488851575508905224089926209249817078392018535"
      "656765998725014589313481039123037168472673687025432538609494741909227605"
      "490712",
      "169934264167910826595765883848459242438990113821003658474365586807299716"
      "288091582927128479661816134640755296117524030297867673457893649404385096"
      "4404405",
      "805268194532540254853221827315978332231079936014530430473277788624701006"
      "514735685778788450107791579012474778927303995844441006517704086579510924"
      "761862",
      "230963978785759186581061685801074935972357439092087595421759455857183039"
      "153374387249363749824041193356507908503626843392136631525715162247529447"
      "0987432",
      "105519520986010126891483687187399511393508357387942516671335364833645284"
      "924809382735285586158960308934616752574535391608949732662773552260135812"
      "0785649",
      "207927227878050728382643818756571136566270610656624150359415237968521633"
      "030902127870054506299201957724950476326586510224673715916605306584145063"
      "4441253",
      "196396116683910993595863068642721163175826841566448628278069269547049949"
      "948718610346946160416690365958206870658902269454382255440698111168442353"
      "5524192",
      "429450322550600283289891166311775461461030276309914725166992747749473739"
      "737643236568408402032463028150942488266038351241904353417501229826560720"
      "600164",
  };
  BigVector modsum3 = BBVfromStrvec(modsum3strvec);
  modsum3.SetModulus(q3);

  std::vector<std::string> moddiff3strvec = {
      "512597535603578636284620600471706441361256218177317597892343972007351046"
      "282937957699448030289016340695226985347494856694864680738501332532337154"
      "369965",
      "125814499093691120338032690878216779743441846858596144716676817186950930"
      "017626310430792135287385954199071188193595635518643737339354403609922433"
      "0319773",
      "805842730693986557467234043205212783543391008567040812905713540778130676"
      "580166107684104083420854024129298497671985888277617739050093011724484112"
      "870671",
      "279930903226674256293076926107048240856889900025849547631231440971971458"
      "024347172924758647932862018727694524150442992033634530795016492509989449"
      "3715533",
      "264768526013493480880410359731886034312242440742790632766905927723999721"
      "803251784267560932081164172028500389468048188373546813123599769653444342"
      "8488350",
      "693199162376459329128054716987553648346475871132117743341660758355345058"
      "542390369742037372302879022664441864154051826106098140959002251215605319"
      "777078",
      "239179774937660057944119797704707816079108412244563858287241292226819675"
      "132815629569566548321767056984321589237526722408984867444636498629084586"
      "3213758",
      "165016581053646305583802200792684936229797960441655784909448934591271278"
      "356760823782530076253342418118532753950587932901212416719129878255565055"
      "545816",
  };
  BigVector moddiff3 = BBVfromStrvec(moddiff3strvec);
  moddiff3.SetModulus(q3);

  std::vector<std::string> modmul3strvec = {
      "103105474514584305682070594578091411828214431081734131021002064062543199"
      "859194040323354510935027293386806050940515736000038934510137289882203635"
      "9679625",
      "398939903363276547750862012224727493964400316336891077935622928183415590"
      "915516500989491410274123740312316424923905334367828029795276021286742965"
      "89001",
      "128157536467338078724788710077393334021754395081595358835203134035411001"
      "404034716438745017724614395885263614546637963247929653182803560261871694"
      "3463922",
      "887662687695833270748810935860224263697693264279486582140404211021156292"
      "460539799921705475485984353404390294379189297326940425588139558557740202"
      "2234",
      "121622288690560069684657414574449533118979023028605797994286236697556812"
      "723191920412097631509792334907416137338053145833489496814685845920501903"
      "5261534",
      "753004725575957473234700352714317139479193934162886068369016394155680048"
      "439319699359431951178436867519868720662245420487511271148333130090416613"
      "227734",
      "278170041094772470035356848898777742997324683492034661632014395564524394"
      "988953631504335262863419941280679588304106553954968793753650103996193140"
      "1092055",
      "477574462920419903543345320561430691498452711801747910227743781056369739"
      "411065806345235440677935972019383967954633150768168291144898135169751571"
      "023658",
  };

  BigVector modmul3 = BBVfromStrvec(modmul3strvec);
  modmul3.SetModulus(q3);

#if 1
  TESTIT(t3, c3, a3 + b3, modsum3, nloop);
  TESTIT(t3, c3, a3.ModAdd(b3), modsum3, nloop);
  TESTIT(t3, c3, a3 - b3, moddiff3, nloop);
  TESTIT(t3, c3, a3.ModSub(b3), moddiff3, nloop);
#endif
  TESTIT(t3, c3, a3 * b3, modmul3, nloop);
  TESTIT(t3, c3, a3.ModMul(b3), modmul3, nloop);

  return;
}
