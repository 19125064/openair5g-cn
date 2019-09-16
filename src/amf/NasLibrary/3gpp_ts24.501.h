/*
 *  This file contains NAS header bits format
 *  Refer TS24.007 TS24.501
 *  Auther: Puzyu Dukl
 *  Time:
 *  Email: hr@
 */

/*Extended Protocol Discriminator (EPD)*/

//8 bits
//big endian
#define _5GSSessionManagementMessages       0b00101110
#define _5GSMobilityManagementMessages      0b01111110


/* Security Header Type*/
//4 bits
#define Plain5GSNASMessage                                          0b0000
#define IntegrityProtected                                          0b0001
#define IntegrityProtectedAndCiphered                               0b0010
#define IntegrityProtectedWithNew5GNASSecurityContext               0b0011
#define IntegrityProtectedAndCipheredWithNew5GNASSecurityContext    0b0100

#define SpareHalfOctet                                              0b0000 /*填充用*/

/* PDU Session Identity */
//8 bits

#define NoPDUSessionIdentityAssigned            0b00000000
#define PDUSessionIdentityValue1                0b00000001
#define PDUSessionIdentityValue2                0b00000010
#define PDUSessionIdentityValue3                0b00000011
#define PDUSessionIdentityValue4                0b00000100
#define PDUSessionIdentityValue5                0b00000101
#define PDUSessionIdentityValue6                0b00000110
#define PDUSessionIdentityValue7                0b00000111
#define PDUSessionIdentityValue8                0b00001000
#define PDUSessionIdentityValue9                0b00001001
#define PDUSessionIdentityValue10               0b00001010
#define PDUSessionIdentityValue11               0b00001011
#define PDUSessionIdentityValue12               0b00001100
#define PDUSessionIdentityValue13               0b00001101
#define PDUSessionIdentityValue14               0b00001110
#define PDUSessionIdentityValue15               0b00001111

/* Procedure transaction identity */
//8 bits
#define NoProcedureTransactionIdentityAssigned      0b00000000
#define ProcedureTransactionIdentityValue0          0b00000001
#define ProcedureTransactionIdentityValue1          0b00000010
#define ProcedureTransactionIdentityValue2          0b00000011
#define ProcedureTransactionIdentityValue3          0b00000100
#define ProcedureTransactionIdentityValue4          0b00000101
#define ProcedureTransactionIdentityValue5          0b00000110
#define ProcedureTransactionIdentityValue6          0b00000111
#define ProcedureTransactionIdentityValue7          0b00001000
#define ProcedureTransactionIdentityValue8          0b00001001
#define ProcedureTransactionIdentityValue9          0b00001010
#define ProcedureTransactionIdentityValue10          0b00001011
#define ProcedureTransactionIdentityValue11          0b00001100
#define ProcedureTransactionIdentityValue12          0b00001101
#define ProcedureTransactionIdentityValue13          0b00001110
#define ProcedureTransactionIdentityValue14          0b00001111
#define ProcedureTransactionIdentityValue15          0b00010000
#define ProcedureTransactionIdentityValue16          0b00010001
#define ProcedureTransactionIdentityValue17          0b00010010
#define ProcedureTransactionIdentityValue18          0b00010011
#define ProcedureTransactionIdentityValue19          0b00010100
#define ProcedureTransactionIdentityValue20          0b00010101
#define ProcedureTransactionIdentityValue21          0b00010110
#define ProcedureTransactionIdentityValue22          0b00010111
#define ProcedureTransactionIdentityValue23          0b00011000
#define ProcedureTransactionIdentityValue24          0b00011001
#define ProcedureTransactionIdentityValue25          0b00011010
#define ProcedureTransactionIdentityValue26          0b00011011
#define ProcedureTransactionIdentityValue27          0b00011100
#define ProcedureTransactionIdentityValue28          0b00011101
#define ProcedureTransactionIdentityValue29          0b00011110
#define ProcedureTransactionIdentityValue30          0b00011111
#define ProcedureTransactionIdentityValue31          0b00100000
#define ProcedureTransactionIdentityValue32          0b00100001
#define ProcedureTransactionIdentityValue33          0b00100010
#define ProcedureTransactionIdentityValue34          0b00100011
#define ProcedureTransactionIdentityValue35          0b00100100
#define ProcedureTransactionIdentityValue36          0b00100101
#define ProcedureTransactionIdentityValue37          0b00100110
#define ProcedureTransactionIdentityValue38          0b00100111
#define ProcedureTransactionIdentityValue39          0b00101000
#define ProcedureTransactionIdentityValue40          0b00101001
#define ProcedureTransactionIdentityValue41          0b00101010
#define ProcedureTransactionIdentityValue42          0b00101011
#define ProcedureTransactionIdentityValue43          0b00101100
#define ProcedureTransactionIdentityValue44          0b00101101
#define ProcedureTransactionIdentityValue45          0b00101110
#define ProcedureTransactionIdentityValue46          0b00101111
#define ProcedureTransactionIdentityValue47          0b00110000
#define ProcedureTransactionIdentityValue48          0b00110001
#define ProcedureTransactionIdentityValue49          0b00110010
#define ProcedureTransactionIdentityValue50          0b00110011
#define ProcedureTransactionIdentityValue51          0b00110100
#define ProcedureTransactionIdentityValue52          0b00110101
#define ProcedureTransactionIdentityValue53          0b00110110
#define ProcedureTransactionIdentityValue54          0b00110111
#define ProcedureTransactionIdentityValue55          0b00111000
#define ProcedureTransactionIdentityValue56          0b00111001
#define ProcedureTransactionIdentityValue57          0b00111010
#define ProcedureTransactionIdentityValue58          0b00111011
#define ProcedureTransactionIdentityValue59          0b00111100
#define ProcedureTransactionIdentityValue60          0b00111101
#define ProcedureTransactionIdentityValue61          0b00111110
#define ProcedureTransactionIdentityValue62          0b00111111
#define ProcedureTransactionIdentityValue63          0b01000000
#define ProcedureTransactionIdentityValue64          0b01000001
#define ProcedureTransactionIdentityValue65          0b01000010
#define ProcedureTransactionIdentityValue66          0b01000011
#define ProcedureTransactionIdentityValue67          0b01000100
#define ProcedureTransactionIdentityValue68          0b01000101
#define ProcedureTransactionIdentityValue69          0b01000110
#define ProcedureTransactionIdentityValue70          0b01000111
#define ProcedureTransactionIdentityValue71          0b01001000
#define ProcedureTransactionIdentityValue72          0b01001001
#define ProcedureTransactionIdentityValue73          0b01001010
#define ProcedureTransactionIdentityValue74          0b01001011
#define ProcedureTransactionIdentityValue75          0b01001100
#define ProcedureTransactionIdentityValue76          0b01001101
#define ProcedureTransactionIdentityValue77          0b01001110
#define ProcedureTransactionIdentityValue78          0b01001111
#define ProcedureTransactionIdentityValue79          0b01010000
#define ProcedureTransactionIdentityValue80          0b01010001
#define ProcedureTransactionIdentityValue81          0b01010010
#define ProcedureTransactionIdentityValue82          0b01010011
#define ProcedureTransactionIdentityValue83          0b01010100
#define ProcedureTransactionIdentityValue84          0b01010101
#define ProcedureTransactionIdentityValue85          0b01010110
#define ProcedureTransactionIdentityValue86          0b01010111
#define ProcedureTransactionIdentityValue87          0b01011000
#define ProcedureTransactionIdentityValue88          0b01011001
#define ProcedureTransactionIdentityValue89          0b01011010
#define ProcedureTransactionIdentityValue90          0b01011011
#define ProcedureTransactionIdentityValue91          0b01011100
#define ProcedureTransactionIdentityValue92          0b01011101
#define ProcedureTransactionIdentityValue93          0b01011110
#define ProcedureTransactionIdentityValue94          0b01011111
#define ProcedureTransactionIdentityValue95          0b01100000
#define ProcedureTransactionIdentityValue96          0b01100001
#define ProcedureTransactionIdentityValue97          0b01100010
#define ProcedureTransactionIdentityValue98          0b01100011
#define ProcedureTransactionIdentityValue99          0b01100100
#define ProcedureTransactionIdentityValue100          0b01100101
#define ProcedureTransactionIdentityValue101          0b01100110
#define ProcedureTransactionIdentityValue102          0b01100111
#define ProcedureTransactionIdentityValue103          0b01101000
#define ProcedureTransactionIdentityValue104          0b01101001
#define ProcedureTransactionIdentityValue105          0b01101010
#define ProcedureTransactionIdentityValue106          0b01101011
#define ProcedureTransactionIdentityValue107          0b01101100
#define ProcedureTransactionIdentityValue108          0b01101101
#define ProcedureTransactionIdentityValue109          0b01101110
#define ProcedureTransactionIdentityValue110          0b01101111
#define ProcedureTransactionIdentityValue111          0b01110000
#define ProcedureTransactionIdentityValue112          0b01110001
#define ProcedureTransactionIdentityValue113          0b01110010
#define ProcedureTransactionIdentityValue114          0b01110011
#define ProcedureTransactionIdentityValue115          0b01110100
#define ProcedureTransactionIdentityValue116          0b01110101
#define ProcedureTransactionIdentityValue117          0b01110110
#define ProcedureTransactionIdentityValue118          0b01110111
#define ProcedureTransactionIdentityValue119          0b01111000
#define ProcedureTransactionIdentityValue120          0b01111001
#define ProcedureTransactionIdentityValue121          0b01111010
#define ProcedureTransactionIdentityValue122          0b01111011
#define ProcedureTransactionIdentityValue123          0b01111100
#define ProcedureTransactionIdentityValue124          0b01111101
#define ProcedureTransactionIdentityValue125          0b01111110
#define ProcedureTransactionIdentityValue126          0b01111111
#define ProcedureTransactionIdentityValue127          0b10000000
#define ProcedureTransactionIdentityValue128          0b10000001
#define ProcedureTransactionIdentityValue129          0b10000010
#define ProcedureTransactionIdentityValue130          0b10000011
#define ProcedureTransactionIdentityValue131          0b10000100
#define ProcedureTransactionIdentityValue132          0b10000101
#define ProcedureTransactionIdentityValue133          0b10000110
#define ProcedureTransactionIdentityValue134          0b10000111
#define ProcedureTransactionIdentityValue135          0b10001000
#define ProcedureTransactionIdentityValue136          0b10001001
#define ProcedureTransactionIdentityValue137          0b10001010
#define ProcedureTransactionIdentityValue138          0b10001011
#define ProcedureTransactionIdentityValue139          0b10001100
#define ProcedureTransactionIdentityValue140          0b10001101
#define ProcedureTransactionIdentityValue141          0b10001110
#define ProcedureTransactionIdentityValue142          0b10001111
#define ProcedureTransactionIdentityValue143          0b10010000
#define ProcedureTransactionIdentityValue144          0b10010001
#define ProcedureTransactionIdentityValue145          0b10010010
#define ProcedureTransactionIdentityValue146          0b10010011
#define ProcedureTransactionIdentityValue147          0b10010100
#define ProcedureTransactionIdentityValue148          0b10010101
#define ProcedureTransactionIdentityValue149          0b10010110
#define ProcedureTransactionIdentityValue150          0b10010111
#define ProcedureTransactionIdentityValue151          0b10011000
#define ProcedureTransactionIdentityValue152          0b10011001
#define ProcedureTransactionIdentityValue153          0b10011010
#define ProcedureTransactionIdentityValue154          0b10011011
#define ProcedureTransactionIdentityValue155          0b10011100
#define ProcedureTransactionIdentityValue156          0b10011101
#define ProcedureTransactionIdentityValue157          0b10011110
#define ProcedureTransactionIdentityValue158          0b10011111
#define ProcedureTransactionIdentityValue159          0b10100000
#define ProcedureTransactionIdentityValue160          0b10100001
#define ProcedureTransactionIdentityValue161          0b10100010
#define ProcedureTransactionIdentityValue162          0b10100011
#define ProcedureTransactionIdentityValue163          0b10100100
#define ProcedureTransactionIdentityValue164          0b10100101
#define ProcedureTransactionIdentityValue165          0b10100110
#define ProcedureTransactionIdentityValue166          0b10100111
#define ProcedureTransactionIdentityValue167          0b10101000
#define ProcedureTransactionIdentityValue168          0b10101001
#define ProcedureTransactionIdentityValue169          0b10101010
#define ProcedureTransactionIdentityValue170          0b10101011
#define ProcedureTransactionIdentityValue171          0b10101100
#define ProcedureTransactionIdentityValue172          0b10101101
#define ProcedureTransactionIdentityValue173          0b10101110
#define ProcedureTransactionIdentityValue174          0b10101111
#define ProcedureTransactionIdentityValue175          0b10110000
#define ProcedureTransactionIdentityValue176          0b10110001
#define ProcedureTransactionIdentityValue177          0b10110010
#define ProcedureTransactionIdentityValue178          0b10110011
#define ProcedureTransactionIdentityValue179          0b10110100
#define ProcedureTransactionIdentityValue180          0b10110101
#define ProcedureTransactionIdentityValue181          0b10110110
#define ProcedureTransactionIdentityValue182          0b10110111
#define ProcedureTransactionIdentityValue183          0b10111000
#define ProcedureTransactionIdentityValue184          0b10111001
#define ProcedureTransactionIdentityValue185          0b10111010
#define ProcedureTransactionIdentityValue186          0b10111011
#define ProcedureTransactionIdentityValue187          0b10111100
#define ProcedureTransactionIdentityValue188          0b10111101
#define ProcedureTransactionIdentityValue189          0b10111110
#define ProcedureTransactionIdentityValue190          0b10111111
#define ProcedureTransactionIdentityValue191          0b11000000
#define ProcedureTransactionIdentityValue192          0b11000001
#define ProcedureTransactionIdentityValue193          0b11000010
#define ProcedureTransactionIdentityValue194          0b11000011
#define ProcedureTransactionIdentityValue195          0b11000100
#define ProcedureTransactionIdentityValue196          0b11000101
#define ProcedureTransactionIdentityValue197          0b11000110
#define ProcedureTransactionIdentityValue198          0b11000111
#define ProcedureTransactionIdentityValue199          0b11001000
#define ProcedureTransactionIdentityValue200          0b11001001
#define ProcedureTransactionIdentityValue201          0b11001010
#define ProcedureTransactionIdentityValue202          0b11001011
#define ProcedureTransactionIdentityValue203          0b11001100
#define ProcedureTransactionIdentityValue204          0b11001101
#define ProcedureTransactionIdentityValue205          0b11001110
#define ProcedureTransactionIdentityValue206          0b11001111
#define ProcedureTransactionIdentityValue207          0b11010000
#define ProcedureTransactionIdentityValue208          0b11010001
#define ProcedureTransactionIdentityValue209          0b11010010
#define ProcedureTransactionIdentityValue210          0b11010011
#define ProcedureTransactionIdentityValue211          0b11010100
#define ProcedureTransactionIdentityValue212          0b11010101
#define ProcedureTransactionIdentityValue213          0b11010110
#define ProcedureTransactionIdentityValue214          0b11010111
#define ProcedureTransactionIdentityValue215          0b11011000
#define ProcedureTransactionIdentityValue216          0b11011001
#define ProcedureTransactionIdentityValue217          0b11011010
#define ProcedureTransactionIdentityValue218          0b11011011
#define ProcedureTransactionIdentityValue219          0b11011100
#define ProcedureTransactionIdentityValue220          0b11011101
#define ProcedureTransactionIdentityValue221          0b11011110
#define ProcedureTransactionIdentityValue222          0b11011111
#define ProcedureTransactionIdentityValue223          0b11100000
#define ProcedureTransactionIdentityValue224          0b11100001
#define ProcedureTransactionIdentityValue225          0b11100010
#define ProcedureTransactionIdentityValue226          0b11100011
#define ProcedureTransactionIdentityValue227          0b11100100
#define ProcedureTransactionIdentityValue228          0b11100101
#define ProcedureTransactionIdentityValue229          0b11100110
#define ProcedureTransactionIdentityValue230          0b11100111
#define ProcedureTransactionIdentityValue231          0b11101000
#define ProcedureTransactionIdentityValue232          0b11101001
#define ProcedureTransactionIdentityValue233          0b11101010
#define ProcedureTransactionIdentityValue234          0b11101011
#define ProcedureTransactionIdentityValue235          0b11101100
#define ProcedureTransactionIdentityValue236          0b11101101
#define ProcedureTransactionIdentityValue237          0b11101110
#define ProcedureTransactionIdentityValue238          0b11101111
#define ProcedureTransactionIdentityValue239          0b11110000
#define ProcedureTransactionIdentityValue240          0b11110001
#define ProcedureTransactionIdentityValue241          0b11110010
#define ProcedureTransactionIdentityValue242          0b11110011
#define ProcedureTransactionIdentityValue243          0b11110100
#define ProcedureTransactionIdentityValue244          0b11110101
#define ProcedureTransactionIdentityValue245          0b11110110
#define ProcedureTransactionIdentityValue246          0b11110111
#define ProcedureTransactionIdentityValue247          0b11111000
#define ProcedureTransactionIdentityValue248          0b11111001
#define ProcedureTransactionIdentityValue249          0b11111010
#define ProcedureTransactionIdentityValue250          0b11111011
#define ProcedureTransactionIdentityValue251          0b11111100
#define ProcedureTransactionIdentityValue252          0b11111101
#define ProcedureTransactionIdentityValue253          0b11111110
#define ProcedureTransactionIdentityValue254          0b11111111
#define ProcedureTransactionIdentityValue255          0b100000000
#define ProcedureTransactionIdentityValue256          0b100000001
#define ProcedureTransactionIdentityValue257          0b100000010
#define ProcedureTransactionIdentityValue258          0b100000011
#define ProcedureTransactionIdentityValue259          0b100000100
#define ProcedureTransactionIdentityValue260          0b100000101
#define ProcedureTransactionIdentityValue261          0b100000110
#define ProcedureTransactionIdentityValue262          0b100000111
#define ProcedureTransactionIdentityValue263          0b100001000
#define ProcedureTransactionIdentityValue264          0b100001001
#define ProcedureTransactionIdentityValue265          0b100001010
#define ProcedureTransactionIdentityValue266          0b100001011
#define ProcedureTransactionIdentityValue267          0b100001100
#define ProcedureTransactionIdentityValue268          0b100001101
#define ProcedureTransactionIdentityValue269          0b100001110
#define ProcedureTransactionIdentityValue270          0b100001111
#define ProcedureTransactionIdentityValue271          0b100010000
#define ProcedureTransactionIdentityValue272          0b100010001
#define ProcedureTransactionIdentityValue273          0b100010010
#define ProcedureTransactionIdentityValue274          0b100010011
#define ProcedureTransactionIdentityValue275          0b100010100
#define ProcedureTransactionIdentityValue276          0b100010101
#define ProcedureTransactionIdentityValue277          0b100010110
#define ProcedureTransactionIdentityValue278          0b100010111
#define ProcedureTransactionIdentityValue279          0b100011000
#define ProcedureTransactionIdentityValue280          0b100011001
#define ProcedureTransactionIdentityValue281          0b100011010
#define ProcedureTransactionIdentityValue282          0b100011011
#define ProcedureTransactionIdentityValue283          0b100011100
#define ProcedureTransactionIdentityValue284          0b100011101
#define ProcedureTransactionIdentityValue285          0b100011110
#define ProcedureTransactionIdentityValue286          0b100011111
#define ProcedureTransactionIdentityValue287          0b100100000
#define ProcedureTransactionIdentityValue288          0b100100001
#define ProcedureTransactionIdentityValue289          0b100100010
#define ProcedureTransactionIdentityValue290          0b100100011
#define ProcedureTransactionIdentityValue291          0b100100100
#define ProcedureTransactionIdentityValue292          0b100100101
#define ProcedureTransactionIdentityValue293          0b100100110
#define ProcedureTransactionIdentityValue294          0b100100111
#define ProcedureTransactionIdentityValue295          0b100101000
#define ProcedureTransactionIdentityValue296          0b100101001
#define ProcedureTransactionIdentityValue297          0b100101010
#define ProcedureTransactionIdentityValue298          0b100101011
#define ProcedureTransactionIdentityValue299          0b100101100
#define ProcedureTransactionIdentityValue300          0b100101101
#define ProcedureTransactionIdentityValue301          0b100101110
#define ProcedureTransactionIdentityValue302          0b100101111
#define ProcedureTransactionIdentityValue303          0b100110000
#define ProcedureTransactionIdentityValue304          0b100110001
#define ProcedureTransactionIdentityValue305          0b100110010
#define ProcedureTransactionIdentityValue306          0b100110011
#define ProcedureTransactionIdentityValue307          0b100110100
#define ProcedureTransactionIdentityValue308          0b100110101
#define ProcedureTransactionIdentityValue309          0b100110110
#define ProcedureTransactionIdentityValue310          0b100110111
#define ProcedureTransactionIdentityValue311          0b100111000
#define ProcedureTransactionIdentityValue312          0b100111001
#define ProcedureTransactionIdentityValue313          0b100111010
#define ProcedureTransactionIdentityValue314          0b100111011
#define ProcedureTransactionIdentityValue315          0b100111100
#define ProcedureTransactionIdentityValue316          0b100111101
#define ProcedureTransactionIdentityValue317          0b100111110
#define ProcedureTransactionIdentityValue318          0b100111111
#define ProcedureTransactionIdentityValue319          0b101000000
#define ProcedureTransactionIdentityValue320          0b101000001
#define ProcedureTransactionIdentityValue321          0b101000010
#define ProcedureTransactionIdentityValue322          0b101000011
#define ProcedureTransactionIdentityValue323          0b101000100
#define ProcedureTransactionIdentityValue324          0b101000101
#define ProcedureTransactionIdentityValue325          0b101000110
#define ProcedureTransactionIdentityValue326          0b101000111
#define ProcedureTransactionIdentityValue327          0b101001000
#define ProcedureTransactionIdentityValue328          0b101001001
#define ProcedureTransactionIdentityValue329          0b101001010
#define ProcedureTransactionIdentityValue330          0b101001011
#define ProcedureTransactionIdentityValue331          0b101001100
#define ProcedureTransactionIdentityValue332          0b101001101
#define ProcedureTransactionIdentityValue333          0b101001110
#define ProcedureTransactionIdentityValue334          0b101001111
#define ProcedureTransactionIdentityValue335          0b101010000
#define ProcedureTransactionIdentityValue336          0b101010001
#define ProcedureTransactionIdentityValue337          0b101010010
#define ProcedureTransactionIdentityValue338          0b101010011
#define ProcedureTransactionIdentityValue339          0b101010100
#define ProcedureTransactionIdentityValue340          0b101010101
#define ProcedureTransactionIdentityValue341          0b101010110
#define ProcedureTransactionIdentityValue342          0b101010111
#define ProcedureTransactionIdentityValue343          0b101011000
#define ProcedureTransactionIdentityValue344          0b101011001
#define ProcedureTransactionIdentityValue345          0b101011010
#define ProcedureTransactionIdentityValue346          0b101011011
#define ProcedureTransactionIdentityValue347          0b101011100
#define ProcedureTransactionIdentityValue348          0b101011101
#define ProcedureTransactionIdentityValue349          0b101011110
#define ProcedureTransactionIdentityValue350          0b101011111
#define ProcedureTransactionIdentityValue351          0b101100000
#define ProcedureTransactionIdentityValue352          0b101100001
#define ProcedureTransactionIdentityValue353          0b101100010
#define ProcedureTransactionIdentityValue354          0b101100011
#define ProcedureTransactionIdentityValue355          0b101100100
#define ProcedureTransactionIdentityValue356          0b101100101
#define ProcedureTransactionIdentityValue357          0b101100110
#define ProcedureTransactionIdentityValue358          0b101100111
#define ProcedureTransactionIdentityValue359          0b101101000
#define ProcedureTransactionIdentityValue360          0b101101001
#define ProcedureTransactionIdentityValue361          0b101101010
#define ProcedureTransactionIdentityValue362          0b101101011
#define ProcedureTransactionIdentityValue363          0b101101100
#define ProcedureTransactionIdentityValue364          0b101101101
#define ProcedureTransactionIdentityValue365          0b101101110
#define ProcedureTransactionIdentityValue366          0b101101111
#define ProcedureTransactionIdentityValue367          0b101110000
#define ProcedureTransactionIdentityValue368          0b101110001
#define ProcedureTransactionIdentityValue369          0b101110010
#define ProcedureTransactionIdentityValue370          0b101110011
#define ProcedureTransactionIdentityValue371          0b101110100
#define ProcedureTransactionIdentityValue372          0b101110101
#define ProcedureTransactionIdentityValue373          0b101110110
#define ProcedureTransactionIdentityValue374          0b101110111
#define ProcedureTransactionIdentityValue375          0b101111000
#define ProcedureTransactionIdentityValue376          0b101111001
#define ProcedureTransactionIdentityValue377          0b101111010
#define ProcedureTransactionIdentityValue378          0b101111011
#define ProcedureTransactionIdentityValue379          0b101111100
#define ProcedureTransactionIdentityValue380          0b101111101
#define ProcedureTransactionIdentityValue381          0b101111110
#define ProcedureTransactionIdentityValue382          0b101111111
#define ProcedureTransactionIdentityValue383          0b110000000
#define ProcedureTransactionIdentityValue384          0b110000001
#define ProcedureTransactionIdentityValue385          0b110000010
#define ProcedureTransactionIdentityValue386          0b110000011
#define ProcedureTransactionIdentityValue387          0b110000100
#define ProcedureTransactionIdentityValue388          0b110000101
#define ProcedureTransactionIdentityValue389          0b110000110
#define ProcedureTransactionIdentityValue390          0b110000111
#define ProcedureTransactionIdentityValue391          0b110001000
#define ProcedureTransactionIdentityValue392          0b110001001
#define ProcedureTransactionIdentityValue393          0b110001010
#define ProcedureTransactionIdentityValue394          0b110001011
#define ProcedureTransactionIdentityValue395          0b110001100
#define ProcedureTransactionIdentityValue396          0b110001101
#define ProcedureTransactionIdentityValue397          0b110001110
#define ProcedureTransactionIdentityValue398          0b110001111
#define ProcedureTransactionIdentityValue399          0b110010000
#define ProcedureTransactionIdentityValue400          0b110010001
#define ProcedureTransactionIdentityValue401          0b110010010
#define ProcedureTransactionIdentityValue402          0b110010011
#define ProcedureTransactionIdentityValue403          0b110010100
#define ProcedureTransactionIdentityValue404          0b110010101
#define ProcedureTransactionIdentityValue405          0b110010110
#define ProcedureTransactionIdentityValue406          0b110010111
#define ProcedureTransactionIdentityValue407          0b110011000
#define ProcedureTransactionIdentityValue408          0b110011001
#define ProcedureTransactionIdentityValue409          0b110011010
#define ProcedureTransactionIdentityValue410          0b110011011
#define ProcedureTransactionIdentityValue411          0b110011100
#define ProcedureTransactionIdentityValue412          0b110011101
#define ProcedureTransactionIdentityValue413          0b110011110
#define ProcedureTransactionIdentityValue414          0b110011111
#define ProcedureTransactionIdentityValue415          0b110100000
#define ProcedureTransactionIdentityValue416          0b110100001
#define ProcedureTransactionIdentityValue417          0b110100010
#define ProcedureTransactionIdentityValue418          0b110100011
#define ProcedureTransactionIdentityValue419          0b110100100
#define ProcedureTransactionIdentityValue420          0b110100101
#define ProcedureTransactionIdentityValue421          0b110100110
#define ProcedureTransactionIdentityValue422          0b110100111
#define ProcedureTransactionIdentityValue423          0b110101000
#define ProcedureTransactionIdentityValue424          0b110101001
#define ProcedureTransactionIdentityValue425          0b110101010
#define ProcedureTransactionIdentityValue426          0b110101011
#define ProcedureTransactionIdentityValue427          0b110101100
#define ProcedureTransactionIdentityValue428          0b110101101
#define ProcedureTransactionIdentityValue429          0b110101110
#define ProcedureTransactionIdentityValue430          0b110101111
#define ProcedureTransactionIdentityValue431          0b110110000
#define ProcedureTransactionIdentityValue432          0b110110001
#define ProcedureTransactionIdentityValue433          0b110110010
#define ProcedureTransactionIdentityValue434          0b110110011
#define ProcedureTransactionIdentityValue435          0b110110100
#define ProcedureTransactionIdentityValue436          0b110110101
#define ProcedureTransactionIdentityValue437          0b110110110
#define ProcedureTransactionIdentityValue438          0b110110111
#define ProcedureTransactionIdentityValue439          0b110111000
#define ProcedureTransactionIdentityValue440          0b110111001
#define ProcedureTransactionIdentityValue441          0b110111010
#define ProcedureTransactionIdentityValue442          0b110111011
#define ProcedureTransactionIdentityValue443          0b110111100
#define ProcedureTransactionIdentityValue444          0b110111101
#define ProcedureTransactionIdentityValue445          0b110111110
#define ProcedureTransactionIdentityValue446          0b110111111
#define ProcedureTransactionIdentityValue447          0b111000000
#define ProcedureTransactionIdentityValue448          0b111000001
#define ProcedureTransactionIdentityValue449          0b111000010
#define ProcedureTransactionIdentityValue450          0b111000011
#define ProcedureTransactionIdentityValue451          0b111000100
#define ProcedureTransactionIdentityValue452          0b111000101
#define ProcedureTransactionIdentityValue453          0b111000110
#define ProcedureTransactionIdentityValue454          0b111000111
#define ProcedureTransactionIdentityValue455          0b111001000
#define ProcedureTransactionIdentityValue456          0b111001001
#define ProcedureTransactionIdentityValue457          0b111001010
#define ProcedureTransactionIdentityValue458          0b111001011
#define ProcedureTransactionIdentityValue459          0b111001100
#define ProcedureTransactionIdentityValue460          0b111001101
#define ProcedureTransactionIdentityValue461          0b111001110
#define ProcedureTransactionIdentityValue462          0b111001111
#define ProcedureTransactionIdentityValue463          0b111010000
#define ProcedureTransactionIdentityValue464          0b111010001
#define ProcedureTransactionIdentityValue465          0b111010010
#define ProcedureTransactionIdentityValue466          0b111010011
#define ProcedureTransactionIdentityValue467          0b111010100
#define ProcedureTransactionIdentityValue468          0b111010101
#define ProcedureTransactionIdentityValue469          0b111010110
#define ProcedureTransactionIdentityValue470          0b111010111
#define ProcedureTransactionIdentityValue471          0b111011000
#define ProcedureTransactionIdentityValue472          0b111011001
#define ProcedureTransactionIdentityValue473          0b111011010
#define ProcedureTransactionIdentityValue474          0b111011011
#define ProcedureTransactionIdentityValue475          0b111011100
#define ProcedureTransactionIdentityValue476          0b111011101
#define ProcedureTransactionIdentityValue477          0b111011110
#define ProcedureTransactionIdentityValue478          0b111011111
#define ProcedureTransactionIdentityValue479          0b111100000
#define ProcedureTransactionIdentityValue480          0b111100001
#define ProcedureTransactionIdentityValue481          0b111100010
#define ProcedureTransactionIdentityValue482          0b111100011
#define ProcedureTransactionIdentityValue483          0b111100100
#define ProcedureTransactionIdentityValue484          0b111100101
#define ProcedureTransactionIdentityValue485          0b111100110
#define ProcedureTransactionIdentityValue486          0b111100111
#define ProcedureTransactionIdentityValue487          0b111101000
#define ProcedureTransactionIdentityValue488          0b111101001
#define ProcedureTransactionIdentityValue489          0b111101010
#define ProcedureTransactionIdentityValue490          0b111101011
#define ProcedureTransactionIdentityValue491          0b111101100
#define ProcedureTransactionIdentityValue492          0b111101101
#define ProcedureTransactionIdentityValue493          0b111101110
#define ProcedureTransactionIdentityValue494          0b111101111
#define ProcedureTransactionIdentityValue495          0b111110000
#define ProcedureTransactionIdentityValue496          0b111110001
#define ProcedureTransactionIdentityValue497          0b111110010
#define ProcedureTransactionIdentityValue498          0b111110011
#define ProcedureTransactionIdentityValue499          0b111110100
#define ProcedureTransactionIdentityValue500          0b111110101
#define ProcedureTransactionIdentityValue501          0b111110110
#define ProcedureTransactionIdentityValue502          0b111110111
#define ProcedureTransactionIdentityValue503          0b111111000
#define ProcedureTransactionIdentityValue504          0b111111001
#define ProcedureTransactionIdentityValue505          0b111111010
#define ProcedureTransactionIdentityValue506          0b111111011
#define ProcedureTransactionIdentityValue507          0b111111100
#define ProcedureTransactionIdentityValue508          0b111111101
#define ProcedureTransactionIdentityValue509          0b111111110


/* Message Type for Mobility Management */

// 0b01******
/* 5GS Mobility Management Messages */

#define REGISTRATION_REQUEST                    0b01000001
#define REGISTRATION_ACCEPT                     0b01000010
#define REGISTRATION_COMPLETE                   0b01000011
#define REGISTRATION_REJECT                     0b01000100
#define DEREGISTRATION_REQUEST_UE_ORIGINATING   0b01000101
#define DEREGISTRATION_ACCEPT_UE_ORIGINATING    0b01000110
#define DEREGISTRATION_REQUEST_UE_TERMINATED    0b01000111
#define DEREGISTRATION_ACCEPT_UE_TERMINATED     0b01001000

#define SERVICE_REQUEST                         0b01001100
#define SERVICE_REJECT                          0b01001101
#define SERVICE_ACCEPT                          0b01001110

#define CONFIGURATION_UPDATE_COMMAND            0b01010100
#define CONFIGURATION_UPDATE_COMPLETE           0b01010101
#define AUTHENTICATION_REQUEST                  0b01010110
#define AUTHENTICATION_RESPONSE                 0b01010111
#define AUTHENTICATION_REJECT                   0b01011000
#define AUTHENTICATION_FAILURE                  0b01011001
#define AUTHENTICATION_RESULT                   0b01011010
#define IDENTITY_REQUEST                        0b01011011
#define IDENTITY_RESPONSE                       0b01011100
#define SECURITY_MODE_COMMAND                   0b01011101
#define SECURITY_MODE_COMPLETE                  0b01011110
#define SECURITY_MODE_REJECT                    0b01011111

#define _5GMM_STATUS                            0b01100100
#define NOTIFICATION                            0b01100101
#define NOTIFICATION_RESPONSE                   0b01100110
#define ULNAS_TRANSPORT                         0b01100111
#define DLNAS_TRANSPORT                         0b01101000


//0b11******
//5GS Session Management Messages

#define PDU_SESSION_ESTABLISHMENT_REQUEST       0b11000001
#define PDU_SESSION_ESTABLISHMENT_ACCPET        0b11000010
#define PDU_SESSION_ESTABLISHMENT_REJECT        0b11000011

#define PDU_SESSION_AUTHENTICATION_COMMAND      0b11000101
#define PDU_SESSION_AUTHENTICATION_COMPLETE     0b11000110
#define PDU_SESSION_AUTHENTICATION_RESULT       0b11000111

#define PDU_SESSION_MODIFICATION_REQUEST        0b11001001
#define PDU_SESSION_MODIFICATION_REJECT         0b11001010
#define PDU_SESSION_MODIFICATION_COMMAND        0b11001011
#define PDU_SESSION_MODIFICATION_COMPLETE       0b11001100
#define PDU_SESSION_MODIFICATION_COMMANDREJECT  0b11001101

#define PDU_SESSION_RELEASE_REQUEST             0b11010001
#define PDU_SESSION_RELEASE_REJECT              0b11010010
#define PDU_SESSION_RELEASE_COMMAND             0b11010011
#define PDU_SESSION_RELEASE_COMPLETE            0b11010100

#define _5GSMStatus                             0b11010110


/*
 * Message Authentication Code
 * 木得定义
 * The message authentication code (MAC) information element contains
 * the integrity protection information for the message.
 */

/*---------------------------------------------------------------------------------------------*/





/*
 * Plain 5GS NAS Message
 *
 * This IE includes a complete plain 5GS NAS message as specified
 * in subclauses 8.2 and 8.3. The SECURITY PROTECTED 5GS NAS MESSAGE message
 * (see subclause 8.2.28) is not plain 5GS NAS messages and shall not be included in this IE.
 */

/*---------------------------------------------------------------------------------------------*/





/*
 *
 * Sequence Number
 *
 * This IE includes the NAS message sequence number (SN)
 * which consists of the eight least significant bits of
 * the NAS COUNT for a SECURITY PROTECTED 5GS NAS MESSAGE message.
 * The usage of SN is specified in subclause 4.4.3.
 *
 */


/*---------------------------------------------------------------------------------------------*/



/*
 * Other information elements
 *
 */


/*---------------------------------------------------------------------------------------------*/


/*
 * 5GMM cause types
*/

#define IIEGAL_UE                         	    0b00000011
#define PEI_NOT_ACCEPTED                        0b00000101
#define IIEGAL_ME                               0b00000110
#define FGS_SERVICES_NOT_ALLOWED                0b00000111
#define IMPLICITLY_DE-REGISTERED                0b00001010
#define PLMN_NOT_ALLOWED                        0b00001011
#define TRACKING_AREA_NOT_ALLOWED               0b00001100
#define ROAMING_NOT_ALLOWED_IN_THIS_TA          0b00001101
//#define
//#define
//#define
//#define
//#define
//#define
//#define
//#define

/*********************************************************************************************/
/*
*  5GS mobile identity information element
*  Type of Identity*/
#define NO_IDENTITY 0b000
#define SUCI        0b001
#define _5G-GUTI    0b110
#define IMEI        0b011
#define _5G-S-TMSI  0b100
#define IMEISVI     0b101

#define EVEN_IENTITY 0
#define ODD_IDENTITY 1
