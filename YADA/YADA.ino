// ---> Ensure this is configured in uBitcoin_conf.h <-------------------
// In .../libraries/uBitcoin/src/uBitcoin_conf.h:
// #define USE_KECCAK 1 // This define controls Keccak compilation within uBitcoin library
// -----------------------------------------------------------------------

#include <Arduino.h>
#include <Bitcoin.h>          // https://github.com/micro-bitcoin/uBitcoin
#include <Networks.h>         // Part of the Bitcoin library
#include <Preferences.h>      // Built-in ESP32 library
#include <QRCodeGenerator.h>  // https://github.com/Tomstark/QRCodeGenerator
#include "bip39_wordlist.h"   // Needs to be included
#include <BigNumber.h>        // For BigNumber-based derivation

#include <mbedtls/sha256.h>
#include <esp_system.h>
#include "esp_heap_caps.h"
#include <stdint.h>
#include <arpa/inet.h>     // For ntohl
#include "string.h"        // For strcmp, strlen, memcpy etc. (standard C string)
#include <stdio.h>         // For sscanf
#include <algorithm>       // For std::min, std::max
#include <ctype.h>         // For toupper, tolower in checksum

// For EVM address generation
extern "C" {
    void keccak_256(const uint8_t *input, size_t len, uint8_t *output);
}

// --- TFT & Touch Libraries ---
#include <SPI.h>
#include <TFT_eSPI.h>
#include <XPT2046_Touchscreen.h>

// --- Pin Definitions ---
#ifndef TFT_BL
  #define TFT_BL 21
#endif
#ifndef TFT_BACKLIGHT_ON
  #define TFT_BACKLIGHT_ON HIGH
#endif
#define TOUCH_CS   33
#define TOUCH_IRQ  36
#define TOUCH_SCK  25
#define TOUCH_MISO 39
#define TOUCH_MOSI 32

// --- Display & Touch Setup ---
TFT_eSPI tft = TFT_eSPI();
SPIClass touchSPI(VSPI);
XPT2046_Touchscreen ts(TOUCH_CS, TOUCH_IRQ);

// --- On-Screen Buttons ---
#define MAX_BUTTONS 5 
TFT_eSPI_Button buttons[MAX_BUTTONS];
#define BUTTON_H 50
#define BUTTON_W 100
#define SECRET_BUTTON_SIZE 35
#define BUTTON_SPACING_X 10
#define BUTTON_SPACING_Y 10

// --- Button Definitions (Indices for drawing & logical mapping) ---
#define BTN_DRAW_YADA   0 
#define BTN_DRAW_ETH    1 
#define BTN_DRAW_BSC    2 
#define BTN_DRAW_LEFT   0 
#define BTN_DRAW_RIGHT  1 
#define BTN_DRAW_SECRET 2 

// --- Preferences ---
Preferences prefs;
const char* PREFS_NAMESPACE = "yada-wallet";
const char* MNEMONIC_KEY = "mnemonic";
const char* PROVISIONED_KEY = "provisioned";

// --- State Variables ---
enum ChainType { CHAIN_YADA, CHAIN_ETH, CHAIN_BSC, NUM_CHAIN_TYPES };
enum AppState {
    STATE_INITIALIZING, STATE_CHAIN_SELECTION, STATE_SHOW_GENERATED_MNEMONIC,
    STATE_PASSWORD_ENTRY, STATE_WALLET_VIEW, STATE_SHOW_SECRET_MNEMONIC, STATE_ERROR
};
AppState currentState = STATE_INITIALIZING;
ChainType selectedChainType = CHAIN_YADA;
AppState lastWalletState = STATE_WALLET_VIEW;
String errorMessage = "";
String generatedMnemonic = "";
String loadedMnemonic = "";
HDPrivateKey hdWalletKeyGlobal; 

// --- Button State (Triggered by specific touch areas defined in readButtons()) ---
bool buttonLeftTriggered = false;
bool buttonRightTriggered = false; 
bool buttonSecretTriggered = false;
bool buttonBottomRightTriggered = false; 
bool touchIsBeingHeld = false; 

// --- Password Entry State ---
const uint32_t MODULO_2_31 = 2147483647; 
const int PIN_LENGTH = 6;
char password[PIN_LENGTH + 1];
int currentDigitIndex = 0;
int currentDigitValue = 0;
bool passwordConfirmed = false;

// --- Wallet View State ---
int currentRotationIndex = 0;
const int MAX_ROTATION_INDEX = 99; 

// ========================================
// Crypto & Utility Functions
// ========================================
String bytesToHex(const uint8_t* b, size_t l){String s="";s.reserve(l*2);for(size_t i=0;i<l;i++){if(b[i]<0x10)s+="0";s+=String(b[i],HEX);}return s;}

bool hexToBytes(const String& hex, uint8_t* bytes, size_t len) {
    if (hex.length() != len * 2) {return false;}
    for (size_t i = 0; i < len; ++i) {
        unsigned int v;
        if (sscanf(hex.substring(i * 2, i * 2 + 2).c_str(), "%2x", &v) != 1) {return false;}
        bytes[i] = (uint8_t)v;
    }
    return true;
}

String ethChecksum(const uint8_t addr[20]) {
  String hexAddr = bytesToHex(addr, 20); 
  char hexChars[41];                     
  hexAddr.toLowerCase();                 
  hexAddr.toCharArray(hexChars, 41);
  uint8_t hashOutput[32]; 
  keccak_256((uint8_t*)hexChars, 40, hashOutput); 
  for (int i = 0; i < 40; ++i) {
    uint8_t hashNibble = (i % 2 == 0) ? (hashOutput[i/2] >> 4) : (hashOutput[i/2] & 0x0f);
    if (hexChars[i] >= 'a' && hexChars[i] <= 'f') { 
        if (hashNibble >= 8) {
            hexChars[i] = toupper(hexChars[i]);
        }
    }
  }
  return String("0x") + hexChars;
}

String getEvmAddress(const HDPrivateKey& hdKey) {
    if (!hdKey.isValid()) {
        Serial.println("E: getEvmAddress: Invalid HDPrivateKey");
        return "EVM Addr Error (Invalid HDKey)";
    }
    PublicKey pubKey = hdKey.publicKey(); 
    pubKey.compressed = false; // EVM needs uncompressed public key
    
    String pubKeyHex = pubKey.toString(); 
    if (pubKeyHex.length() != 130 || !pubKeyHex.startsWith("04")) {
        Serial.printf("E: getEvmAddress: PubKey toString() unexpected. Len: %d, Starts: %s\n", pubKeyHex.length(), pubKeyHex.substring(0,2).c_str());
        return "EVM Addr Error (PubKey Format)";
    }
    uint8_t uncompressedPubKeyBytesWithPrefix[65];
    if (!hexToBytes(pubKeyHex, uncompressedPubKeyBytesWithPrefix, 65)) {
         return "EVM Addr Error (Parse PubKeyHex)";
    }
    uint8_t pubKeyXY[64]; 
    memcpy(pubKeyXY, uncompressedPubKeyBytesWithPrefix + 1, 64); 
    uint8_t keccakHash[32];
    keccak_256(pubKeyXY, 64, keccakHash); 
    uint8_t addressBytes[20];
    memcpy(addressBytes, keccakHash + 12, 20); 
    return ethChecksum(addressBytes);
}

int hexCharToDec(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return -1; 
}

BigNumber hexToBigNumber(const char* hex) {
    BigNumber result = 0;
    for (const char* p = hex; *p != '\0'; ++p) {
        int digit = hexCharToDec(*p);
        if (digit < 0) { continue; }
        result *= 16;
        result += digit;
    }
    return result;
}

uint32_t deriveIndex(String factor, int level) { 
    BigNumber::begin();
    String combined = factor + String(level);
    unsigned char hash_val[32]; 
    mbedtls_sha256((const unsigned char*)combined.c_str(), combined.length(), hash_val, 0);
    char hex_str[65]; 
    for (int i = 0; i < 32; i++) { sprintf(&hex_str[i * 2], "%02x", hash_val[i]); }
    BigNumber bigNum = hexToBigNumber(hex_str);
    BigNumber modulo(MODULO_2_31);
    BigNumber remainder_bn = bigNum % modulo;
    BigNumber::finish();
    unsigned long val_ul = 0; 
    String remainder_str = remainder_bn.toString();
    sscanf(remainder_str.c_str(), "%lu", &val_ul); 
    return (uint32_t)val_ul;
}

HDPrivateKey deriveHardened(HDPrivateKey root, uint32_t index) { 
    String path = String(index) + "'";
    HDPrivateKey key = root.derive(path.c_str());
    if (!key.isValid()) { Serial.println("E: deriveHardened failed for path: " + path); }
    return key;
}

HDPrivateKey deriveSecurePath(HDPrivateKey root, String secondFactor) { 
    HDPrivateKey currentNode = root;
    for (int level = 0; level < 4; level++) {
        uint32_t index = deriveIndex(secondFactor, level); 
        currentNode = deriveHardened(currentNode, index);
        if (!currentNode.isValid()) {
            Serial.println("E: deriveSecurePath failed at level " + String(level) + " for index " + String(index));
            break; 
        }
    }
    return currentNode;
}

String generateMnemonicFromEntropy(const uint8_t* e, size_t len){if(len!=16)return""; uint8_t cs_len=(len*8)/32; uint8_t h[32]; mbedtls_sha256_context c; mbedtls_sha256_init(&c); mbedtls_sha256_starts(&c,0); mbedtls_sha256_update(&c,e,len); mbedtls_sha256_finish(&c,h); mbedtls_sha256_free(&c); uint8_t cs_byte=h[0]; uint8_t mask=0xFF<<(8-cs_len); uint8_t cs_bits=cs_byte&mask; int total_bits=(len*8)+cs_len; int num_words=total_bits/11; String m=""; m.reserve(120); uint16_t w_idx=0; int bit_count=0; for(int i=0;i<total_bits;i++){int byte_idx=i/8; int bit_in_byte=7-(i%8); uint8_t curr_byte; if(byte_idx<len){curr_byte=e[byte_idx];}else{int cs_bit_idx=i-(len*8); int shift=7-cs_bit_idx; curr_byte=cs_bits; bit_in_byte=shift;} uint8_t bit_val=(curr_byte>>bit_in_byte)&1; w_idx=(w_idx<<1)|bit_val; bit_count++; if(bit_count==11){if(w_idx>=2048)return""; m+=String(wordlist[w_idx]); if((i+1)<total_bits)m+=" "; w_idx=0; bit_count=0;}} return m;}

// ========================================
// Display Functions
// ========================================
void drawButtons(int numButtons) { for(int i=0; i<numButtons && i<MAX_BUTTONS; i++) buttons[i].drawButton(); }

void displayErrorScreen(String msg) {
    tft.fillScreen(TFT_RED); tft.setTextColor(TFT_WHITE,TFT_RED); tft.setTextDatum(MC_DATUM);
    tft.setTextSize(2); tft.drawString("ERROR", tft.width()/2, 30);
    tft.drawFastHLine(10,50,tft.width()-20,TFT_WHITE); tft.setTextDatum(TL_DATUM);
    tft.setTextSize(1); tft.setCursor(10,65); int maxC=(tft.width()-20)/tft.textWidth("W"); String cL=""; 
    for(unsigned int i=0;i<msg.length();i++){char ch=msg.charAt(i); cL+=ch; if((ch==' '&&cL.length()>= (unsigned int)maxC)||cL.length()>(unsigned int)maxC+10){int wP=-1; if(ch!=' '){for(int j=cL.length()-1;j>=0;j--) if(cL[j]==' '){wP=j;break;}}else{wP=cL.length()-1;} if(wP!=-1){tft.println(cL.substring(0,wP)); cL=cL.substring(wP+1);} else{tft.println(cL); cL="";} tft.setCursor(10,tft.getCursorY()); if(tft.getCursorY()>tft.height()-BUTTON_H-30){tft.print("...");break;}}} if(cL.length()>0)tft.println(cL);
    int okButtonCenterX = 65; int okButtonCenterY = 205;
    buttons[BTN_DRAW_LEFT].initButton(&tft, okButtonCenterX, okButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_DARKGREY, TFT_BLACK, "OK", 2);
    drawButtons(1); currentState=STATE_ERROR;
}

void displayGeneratedMnemonicScreen(String m) {
    tft.fillScreen(TFT_BLACK); tft.setTextColor(TFT_YELLOW,TFT_BLACK); tft.setTextDatum(MC_DATUM);
    tft.setTextSize(2); tft.drawString("BACKUP MNEMONIC!",tft.width()/2, 20);
    tft.drawFastHLine(10,35,tft.width()-20,TFT_YELLOW); tft.setTextColor(TFT_WHITE,TFT_BLACK);
    tft.setTextDatum(TL_DATUM); tft.setTextSize(1); tft.setTextFont(2);
    int wc=0; String cw=""; String tM=m+" "; int xS=15, yS=55, cW=tft.width()/3-5, lH=tft.fontHeight(2)+3; int xP=xS, yP=yS;
    for(unsigned int i=0;i<tM.length();i++){char c=tM.charAt(i); if(c==' '){if(cw.length()>0){wc++; String wn=String(wc)+"."; tft.setTextColor(TFT_CYAN); tft.drawString(wn,xP,yP); tft.setTextColor(TFT_WHITE); tft.drawString(cw,xP+tft.textWidth("XX."),yP); cw=""; yP+=lH; if(wc%4==0){xP+=cW; yP=yS;} if(wc>=12)break;}} else cw+=c;}
    int confirmButtonCenterX = 255; int confirmButtonCenterY = 205;
    buttons[BTN_DRAW_RIGHT].initButton(&tft, confirmButtonCenterX, confirmButtonCenterY, BUTTON_W+40, BUTTON_H, TFT_WHITE, TFT_GREEN, TFT_BLACK, "Backed Up", 2);
    buttons[BTN_DRAW_RIGHT].drawButton();
}

void displaySecretMnemonicScreen(String m) {
    tft.fillScreen(TFT_BLACK); tft.setTextColor(TFT_ORANGE,TFT_BLACK); tft.setTextDatum(MC_DATUM);
    tft.setTextSize(2); tft.drawString("Root Mnemonic",tft.width()/2, 20);
    tft.drawFastHLine(10,35,tft.width()-20,TFT_ORANGE); tft.setTextColor(TFT_WHITE,TFT_BLACK);
    tft.setTextDatum(TL_DATUM); tft.setTextSize(1); tft.setTextFont(2);
    int wc=0; String cw=""; String tM=m+" "; int xS=15, yS=55, cW=tft.width()/3-5, lH=tft.fontHeight(2)+3; int xP=xS, yP=yS;
    for(unsigned int i=0;i<tM.length();i++){char c=tM.charAt(i); if(c==' '){if(cw.length()>0){wc++; String wn=String(wc)+"."; tft.setTextColor(TFT_CYAN); tft.drawString(wn,xP,yP); tft.setTextColor(TFT_WHITE); tft.drawString(cw,xP+tft.textWidth("XX."),yP); cw=""; yP+=lH; if(wc%4==0){xP+=cW; yP=yS;} if(wc>=12)break;}} else cw+=c;}
    int backButtonCenterX = 65; int backButtonCenterY = 205;
    buttons[BTN_DRAW_LEFT].initButton(&tft, backButtonCenterX, backButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "Back", 2);
    drawButtons(1);
}

void showPasswordEntryScreen() {
    tft.fillScreen(TFT_DARKCYAN); tft.setTextColor(TFT_WHITE, TFT_DARKCYAN);
    tft.setTextDatum(MC_DATUM); tft.setTextSize(2);
    String chainLabel;
    switch(selectedChainType) { case CHAIN_YADA: chainLabel="Yada"; break; case CHAIN_ETH: chainLabel="ETH"; break; case CHAIN_BSC: chainLabel="BSC"; break; default: chainLabel="Wallet"; break;}
    tft.drawString("Enter "+chainLabel+" PIN", tft.width() / 2, 30);

    int digitBoxSize = 25; int spacing = 8;
    int totalW = PIN_LENGTH * digitBoxSize + (PIN_LENGTH - 1) * spacing;
    int startX = (tft.width()-totalW)/2; int digitY = 80;
    tft.setTextSize(2); tft.setTextDatum(MC_DATUM);
    for (int i = 0; i < PIN_LENGTH; i++) {
        int currentX = startX + i * (digitBoxSize + spacing);
        uint16_t boxColor = (i == currentDigitIndex) ? TFT_YELLOW : TFT_WHITE;
        tft.drawRect(currentX, digitY, digitBoxSize, digitBoxSize, boxColor);
        char displayChar;
        if (i < currentDigitIndex) { displayChar = '*'; }
        else if (i == currentDigitIndex) { displayChar = currentDigitValue + '0'; }
        else { displayChar = '_'; }
        char tempStr[2] = {displayChar, '\0'};
        tft.drawString(tempStr, currentX + digitBoxSize / 2 +1, digitY + digitBoxSize / 2 + 1);
    }
    char nextLabel[5] = "Next"; if (currentDigitIndex == PIN_LENGTH - 1) { strcpy(nextLabel, "OK"); }

    int leftButtonCenterX = 65;   int leftButtonCenterY = 205;
    int rightButtonCenterX = 255; int rightButtonCenterY = 205;

    buttons[BTN_DRAW_LEFT].initButton(&tft, leftButtonCenterX, leftButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "Cycle", 2);
    buttons[BTN_DRAW_RIGHT].initButton(&tft, rightButtonCenterX, rightButtonCenterY, BUTTON_W, BUTTON_H, TFT_WHITE, TFT_GREEN, TFT_BLACK, nextLabel, 2);
    drawButtons(2);
}

void displayChainSelectionScreen() {
    tft.fillScreen(TFT_NAVY);
    tft.setTextColor(TFT_WHITE, TFT_NAVY);
    tft.setTextDatum(MC_DATUM);
    tft.drawString("Select Chain", tft.width() / 2, 30, 4);

    int btnW = BUTTON_W + 40;
    int btnH = BUTTON_H + 10;
    int centerX = tft.width() / 2;
    int spacing = 15;
    int btnYadaY = 80;
    int btnEthY  = btnYadaY + btnH + spacing;
    int btnBscY  = btnEthY + btnH + spacing;

    buttons[BTN_DRAW_YADA].initButton(&tft, centerX, btnYadaY, btnW, btnH, TFT_WHITE, TFT_ORANGE, TFT_BLACK, "YADA", 2);
    buttons[BTN_DRAW_ETH].initButton(&tft, centerX, btnEthY, btnW, btnH, TFT_WHITE, TFT_CYAN, TFT_BLACK, "ETH", 2);
    buttons[BTN_DRAW_BSC].initButton(&tft, centerX, btnBscY, btnW, btnH, TFT_WHITE, TFT_YELLOW, TFT_BLACK, "BSC", 2);
    drawButtons(3);
}

void displaySingleRotationQR(int rIdx, const String& combinedQRData, const String& label, int qrVersionAttempt) {
    if(combinedQRData.length() == 0){ displayErrorScreen("QR Gen Error (Empty)"); return; }
    const int eccLevel = ECC_LOW; QRCode qr;
    int currentQrVersion = qrVersionAttempt; if (currentQrVersion < 1) currentQrVersion = 1;
    const int MAX_QR_VERSION_ATTEMPT = 15;

    while(currentQrVersion <= MAX_QR_VERSION_ATTEMPT) {
        size_t bufferSize = qrcode_getBufferSize(currentQrVersion);
        if (bufferSize == 0 || bufferSize > 4000) { currentQrVersion++; continue; }
        uint8_t *qrDataBuffer = (uint8_t *)malloc(bufferSize);
        if (!qrDataBuffer) { displayErrorScreen("QR Buf Alloc V" + String(currentQrVersion)); return; }

        if (qrcode_initText(&qr, qrDataBuffer, currentQrVersion, eccLevel, combinedQRData.c_str()) == 0) {
            tft.fillScreen(TFT_WHITE); tft.setTextColor(TFT_BLACK, TFT_WHITE);
            int topMargin = 2, titleHeight = 18, bottomMargin = 2, buttonAreaHeight = BUTTON_H + BUTTON_SPACING_Y, sideMargin = 4;
            int availableHeight = tft.height() - topMargin - titleHeight - bottomMargin - buttonAreaHeight;
            int availableWidth = tft.width() - 2 * sideMargin;
            int pixelSize = 1; if (qr.size > 0) { int psW=availableWidth/qr.size; int psH=availableHeight/qr.size; pixelSize=std::min(psW,psH); if(pixelSize<1)pixelSize=1; pixelSize=std::min(pixelSize, 4); }
            int qrDrawSize = qr.size * pixelSize; int startX = sideMargin + (availableWidth - qrDrawSize) / 2; int startY = topMargin + titleHeight + (availableHeight - qrDrawSize) / 2;

            tft.setTextDatum(TC_DATUM); tft.setTextSize(1);
            String title = label + " Rot: "+String(rIdx) ;
            tft.drawString(title, tft.width()/2, topMargin, 2);
            for (uint8_t y_qr = 0; y_qr < qr.size; y_qr++) { for (uint8_t x_qr = 0; x_qr < qr.size; x_qr++) { if (qrcode_getModule(&qr, x_qr, y_qr)) { if (pixelSize == 1) tft.drawPixel(startX + x_qr, startY + y_qr, TFT_BLACK); else tft.fillRect(startX + x_qr * pixelSize, startY + y_qr * pixelSize, pixelSize, pixelSize, TFT_BLACK); } } }

            int prevButtonCenterX = 65;    
            int prevButtonCenterY = 205;
            int nextButtonVisualCenterX = 255; 
            int nextButtonVisualCenterY = 205;
            int secretButtonCenterX = tft.width() - (SECRET_BUTTON_SIZE / 2) - 5; 
            int secretButtonCenterY = (SECRET_BUTTON_SIZE / 2) + 5;

            buttons[BTN_DRAW_LEFT].initButton(&tft, prevButtonCenterX, prevButtonCenterY, BUTTON_W + 20, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "< Prev", 2);
            buttons[BTN_DRAW_RIGHT].initButton(&tft, nextButtonVisualCenterX, nextButtonVisualCenterY, BUTTON_W + 20, BUTTON_H, TFT_WHITE, TFT_BLUE, TFT_BLACK, "Next >", 2); 
            buttons[BTN_DRAW_SECRET].initButton(&tft, secretButtonCenterX, secretButtonCenterY, SECRET_BUTTON_SIZE, SECRET_BUTTON_SIZE, TFT_WHITE, TFT_ORANGE, TFT_BLACK, "...", 1);
            
            drawButtons(3); free(qrDataBuffer); return;
        } else { free(qrDataBuffer); currentQrVersion++; }
    }
    displayErrorScreen("QR Init All Fail V" + String(MAX_QR_VERSION_ATTEMPT));
}

// ========================================
// Touch Button Handling
// ========================================
const int ORIG_BL_AREA[4] = {15, 115, 180, 230};  
const int ORIG_TL_AREA[4] = {-15, 85, 20, 70};    
const int ORIG_TR_AREA[4] = {282, 318, 2, 38};    
// const int WALLET_BR_AREA[4] = {205, 305, 180, 230}; // This area is only for visual button, action is via ORIG_TL_AREA

const int CHAIN_SELECT_YADA_AREA[4] = {180, 250, 100, 140}; 
const int CHAIN_SELECT_ETH_AREA[4]  = {80, 130, 100, 140};  
const int CHAIN_SELECT_BSC_AREA[4]  = {0, 60, 100, 140};    

void readButtons() {
    uint16_t t_x = 0, t_y = 0;
    static int touch_start_area_id = -1; 
    buttonLeftTriggered = false; buttonRightTriggered = false;
    buttonSecretTriggered = false; buttonBottomRightTriggered = false; 
    bool is_currently_pressed = ts.tirqTouched() && ts.touched();

    if (is_currently_pressed) {
        TS_Point p = ts.getPoint();
        t_x = map(p.y, 338, 3739, tft.width(), 0); 
        t_y = map(p.x, 414, 3857, tft.height(), 0);
        t_x = constrain(t_x, 0, tft.width() - 1); t_y = constrain(t_y, 0, tft.height() - 1);
        
        if (!touchIsBeingHeld) { 
            touchIsBeingHeld = true; touch_start_area_id = -1; 
            if (currentState == STATE_CHAIN_SELECTION) {
                if (t_x >= CHAIN_SELECT_BSC_AREA[0] && t_x <= CHAIN_SELECT_BSC_AREA[1] && t_y >= CHAIN_SELECT_BSC_AREA[2] && t_y <= CHAIN_SELECT_BSC_AREA[3]) touch_start_area_id = 0; 
                else if (t_x >= CHAIN_SELECT_YADA_AREA[0] && t_x <= CHAIN_SELECT_YADA_AREA[1] && t_y >= CHAIN_SELECT_YADA_AREA[2] && t_y <= CHAIN_SELECT_YADA_AREA[3]) touch_start_area_id = 1; 
                else if (t_x >= CHAIN_SELECT_ETH_AREA[0] && t_x <= CHAIN_SELECT_ETH_AREA[1] && t_y >= CHAIN_SELECT_ETH_AREA[2] && t_y <= CHAIN_SELECT_ETH_AREA[3]) touch_start_area_id = 2; 
            } else { 
                if (t_x >= ORIG_BL_AREA[0] && t_x <= ORIG_BL_AREA[1] && t_y >= ORIG_BL_AREA[2] && t_y <= ORIG_BL_AREA[3]) touch_start_area_id = 0; 
                else if (t_x >= ORIG_TL_AREA[0] && t_x <= ORIG_TL_AREA[1] && t_y >= ORIG_TL_AREA[2] && t_y <= ORIG_TL_AREA[3]) touch_start_area_id = 1; 
                else if (t_x >= ORIG_TR_AREA[0] && t_x <= ORIG_TR_AREA[1] && t_y >= ORIG_TR_AREA[2] && t_y <= ORIG_TR_AREA[3]) touch_start_area_id = 2; 
            }
        }
    } else { 
        if (touchIsBeingHeld) { 
            touchIsBeingHeld = false;
            if (currentState == STATE_CHAIN_SELECTION) {
                if (touch_start_area_id == 0) buttonLeftTriggered = true;  
                else if (touch_start_area_id == 1) buttonRightTriggered = true; 
                else if (touch_start_area_id == 2) buttonSecretTriggered = true;
            } else { 
                if (touch_start_area_id == 0) buttonLeftTriggered = true;    
                else if (touch_start_area_id == 1) buttonRightTriggered = true;    
                else if (touch_start_area_id == 2) buttonSecretTriggered = true;  
            }
            touch_start_area_id = -1; 
        }
    }
}

// ========================================
// Setup Function
// ========================================
void setup() {
  Serial.begin(115200); while (!Serial && millis() < 2000);
  Serial.println("\n\n--- Yada HW Multi-Chain (BigNumber Deriv, EVM Addr, Orig Wallet Touch FINAL) ---"); // Updated title for clarity
  Serial.print("Setup: Init Heap: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
  pinMode(TOUCH_IRQ, INPUT); tft.init(); tft.setRotation(3); tft.fillScreen(TFT_BLACK);
  Serial.println("Setup: TFT OK (Rotation 3).");
  touchSPI.begin(TOUCH_SCK, TOUCH_MISO, TOUCH_MOSI, TOUCH_CS); ts.begin(touchSPI); ts.setRotation(tft.getRotation());
  Serial.println("Setup: Touch OK.");
  pinMode(TFT_BL, OUTPUT); digitalWrite(TFT_BL, TFT_BACKLIGHT_ON); Serial.println("Setup: BL OK.");
  tft.setTextColor(TFT_WHITE, TFT_BLACK); tft.setTextDatum(MC_DATUM); tft.drawString("Initializing...", tft.width() / 2, tft.height() / 2, 4); delay(1000);
  memset(password, '_', PIN_LENGTH); password[PIN_LENGTH]='\0';
  currentDigitIndex = 0; currentDigitValue = 0; passwordConfirmed = false;
  if (!prefs.begin(PREFS_NAMESPACE, false)) {
    Serial.println("W: Prefs RW Fail. Trying RO...");
    if (!prefs.begin(PREFS_NAMESPACE, true)) {
      Serial.println("E: Prefs RO Fail! Storage Error."); tft.fillScreen(TFT_RED); tft.setTextColor(TFT_WHITE);
      tft.drawString("Storage Error!", tft.width()/2, tft.height()/2, 2); while(1) delay(1000);
    } else { Serial.println("Setup: Prefs RO OK."); prefs.end(); }
  } else { Serial.println("Setup: Prefs RW OK."); prefs.end(); }
  currentState = STATE_CHAIN_SELECTION; Serial.println("Setup: Init state -> CHAIN_SELECTION.");
  Serial.print("Setup: Exit Heap: "); Serial.println(heap_caps_get_free_size(MALLOC_CAP_DEFAULT)); Serial.println("Setup OK.");
}

// ========================================
// Main Loop
// ========================================
void loop() {
  static AppState lastState = STATE_INITIALIZING;
  bool redrawScreen = (currentState != lastState);
  static bool firstLoop = true; if(firstLoop){ redrawScreen = true; firstLoop = false;}

  if (redrawScreen) {
    lastState = currentState; buttonLeftTriggered = false; buttonRightTriggered = false;
    buttonSecretTriggered = false; buttonBottomRightTriggered = false; touchIsBeingHeld = false;
    switch (currentState) {
        case STATE_CHAIN_SELECTION: displayChainSelectionScreen(); break;
        case STATE_SHOW_GENERATED_MNEMONIC: displayGeneratedMnemonicScreen(generatedMnemonic); break;
        case STATE_PASSWORD_ENTRY: showPasswordEntryScreen(); break;
        case STATE_SHOW_SECRET_MNEMONIC: displaySecretMnemonicScreen(loadedMnemonic); break;
        default: break;
    }
  }
  readButtons();

  switch (currentState) {
    case STATE_INITIALIZING: errorMessage="Init Loop Error"; displayErrorScreen(errorMessage); break;
    case STATE_CHAIN_SELECTION:
        if (buttonLeftTriggered) { selectedChainType = CHAIN_BSC; currentState = STATE_PASSWORD_ENTRY;} 
        else if (buttonRightTriggered) { selectedChainType = CHAIN_YADA; currentState = STATE_PASSWORD_ENTRY;} 
        else if (buttonSecretTriggered) { selectedChainType = CHAIN_ETH; currentState = STATE_PASSWORD_ENTRY;}
        if(buttonLeftTriggered || buttonRightTriggered || buttonSecretTriggered) Serial.println("L: Chain Selected");
        break;
    case STATE_SHOW_GENERATED_MNEMONIC:
        if(buttonRightTriggered){
             bool sM=false,sF=false;
             if(prefs.begin(PREFS_NAMESPACE,false)){ if(prefs.putString(MNEMONIC_KEY,generatedMnemonic.c_str())) sM=true; if(sM&&prefs.putBool(PROVISIONED_KEY,true)) sF=true; prefs.end(); }
             else { errorMessage="Mnem Save: Prefs Write Err!"; displayErrorScreen(errorMessage); break; }
             if(sM&&sF){ loadedMnemonic=generatedMnemonic; generatedMnemonic=""; currentState=STATE_PASSWORD_ENTRY; passwordConfirmed=false; currentDigitIndex=0; currentDigitValue=0; memset(password,'_',PIN_LENGTH); password[PIN_LENGTH]='\0'; Serial.println("L: Mnem Saved OK -> Re-enter PIN");}
             else { errorMessage="Mnem Save: Key Save Fail!"; displayErrorScreen(errorMessage); }
        }
        break;
    case STATE_PASSWORD_ENTRY:
        if (buttonLeftTriggered) { currentDigitValue = (currentDigitValue + 1) % 10; showPasswordEntryScreen(); } 
        else if (buttonRightTriggered) {
            password[currentDigitIndex] = currentDigitValue + '0'; currentDigitIndex++; currentDigitValue = 0;
            if (currentDigitIndex >= PIN_LENGTH) {
                password[PIN_LENGTH] = '\0'; passwordConfirmed = true; Serial.print("L: PIN Entered");
                bool isProv = false;
                if(prefs.begin(PREFS_NAMESPACE, true)){
                    isProv = prefs.getBool(PROVISIONED_KEY, false);
                    if (isProv && prefs.isKey(MNEMONIC_KEY)) {
                        loadedMnemonic = prefs.getString(MNEMONIC_KEY, "");
                        if (loadedMnemonic.length() < 10) { isProv = false; loadedMnemonic = "";}
                    } else if (isProv) { isProv = false;} 
                    prefs.end();
                } else { errorMessage="PIN: Prefs Read Err!"; displayErrorScreen(errorMessage); break; }
                
                if(isProv && loadedMnemonic.length() > 0){
                    HDPrivateKey masterKey(loadedMnemonic.c_str(), "", &Mainnet);
                    if(!masterKey.isValid()){ errorMessage="Master Key Invalid!"; displayErrorScreen(errorMessage); break; }
                    HDPrivateKey pinLevel0Key = masterKey.derive("0'"); 
                    if(!pinLevel0Key.isValid()){ errorMessage="0' Key Invalid!"; displayErrorScreen(errorMessage); break; }
                    hdWalletKeyGlobal = deriveSecurePath(pinLevel0Key, String(password)); 
                    if(!hdWalletKeyGlobal.isValid()){
                        errorMessage="Wallet Key Deriv Fail!"; displayErrorScreen(errorMessage); 
                        passwordConfirmed = false; currentDigitIndex = 0; currentDigitValue = 0;
                        memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0';
                        break; 
                    }
                    currentState = STATE_WALLET_VIEW; currentRotationIndex = 0; Serial.println(" -> Wallet");
                } else if (!isProv) { 
                     uint8_t ent[16]; esp_fill_random(ent,16); generatedMnemonic = generateMnemonicFromEntropy(ent,16);
                     if(generatedMnemonic.length() > 0){ currentState = STATE_SHOW_GENERATED_MNEMONIC; Serial.println(" -> Gen Mnem"); }
                     else { errorMessage="Key Gen Fail!"; displayErrorScreen(errorMessage); passwordConfirmed=false; currentDigitIndex=0; currentDigitValue=0; memset(password,'_',PIN_LENGTH); password[PIN_LENGTH]='\0';}
                } else { 
                    errorMessage="Mnem Load Fail (PIN)"; displayErrorScreen(errorMessage);
                    passwordConfirmed = false; currentDigitIndex = 0; currentDigitValue = 0;
                    memset(password, '_', PIN_LENGTH); password[PIN_LENGTH] = '\0';
                }
            } else { showPasswordEntryScreen(); }
        }
        break;
    case STATE_WALLET_VIEW: {
        bool walletNeedsRedrawLocal = redrawScreen; lastWalletState = STATE_WALLET_VIEW;

        if(buttonSecretTriggered) { currentState = STATE_SHOW_SECRET_MNEMONIC; goto end_wallet_view_logic;}
        else if(buttonLeftTriggered) { currentRotationIndex = (currentRotationIndex == 0) ? MAX_ROTATION_INDEX : currentRotationIndex - 1; walletNeedsRedrawLocal = true;}
        else if(buttonRightTriggered) { currentRotationIndex = (currentRotationIndex + 1) % (MAX_ROTATION_INDEX + 1); walletNeedsRedrawLocal = true;}
        // buttonBottomRightTriggered is not used for actions in this wallet view configuration.

        if (walletNeedsRedrawLocal) { 
             if(loadedMnemonic.length()==0){errorMessage="Mnem Missing!"; displayErrorScreen(errorMessage); goto end_wallet_view_logic;}
             if(!passwordConfirmed){errorMessage="PIN Not Confirmed"; displayErrorScreen(errorMessage); goto end_wallet_view_logic;}
             if(!hdWalletKeyGlobal.isValid()){errorMessage="Global WalletKey Invalid!"; displayErrorScreen(errorMessage); goto end_wallet_view_logic;}

             String dL="",bPS_str=""; int eQV=8; 
             HDPrivateKey chainRootKey;
             bool isEvmChainFormat = false; 

             switch(selectedChainType){
                case CHAIN_YADA:dL="Yada";bPS_str="0'"; isEvmChainFormat = false; eQV=11; break; 
                case CHAIN_ETH:dL="ETH";bPS_str="1'"; isEvmChainFormat = true; eQV=11; break;  // eQV stays 11 due to long QR
                case CHAIN_BSC:dL="BSC";bPS_str="2'"; isEvmChainFormat = true; eQV=11; break;  // eQV stays 11 due to long QR
                default:errorMessage="Bad Chain";displayErrorScreen(errorMessage);goto end_wallet_view_logic;
             }
             chainRootKey = hdWalletKeyGlobal.derive(bPS_str.c_str());
             if(!chainRootKey.isValid()){errorMessage=dL+" ChainRoot ("+bPS_str+") Fail"; displayErrorScreen(errorMessage);goto end_wallet_view_logic;}

            HDPrivateKey parentKeyForRotation = chainRootKey;
            for (int r = 0; r < currentRotationIndex; r++) {
                String rotationPathSegment = "";
                for (int l_rot = 0; l_rot < 4; l_rot++) { 
                    uint32_t index = deriveIndex(String(password), l_rot); 
                    rotationPathSegment += (l_rot > 0 ? "/" : "") + String(index) + "'";
                }
                parentKeyForRotation = parentKeyForRotation.derive(rotationPathSegment.c_str());
                if (!parentKeyForRotation.isValid()) { errorMessage = dL + " Rot Key Fail"; displayErrorScreen(errorMessage); goto end_wallet_view_logic; }
            }
            HDPrivateKey key_for_addr_n = parentKeyForRotation;

            String path_segment_for_plus1 = ""; 
            for (int l_p1 = 0; l_p1 < 4; l_p1++) { uint32_t index = deriveIndex(String(password), l_p1); path_segment_for_plus1 += (l_p1 > 0 ? "/" : "") + String(index) + "'"; }
            HDPrivateKey key_for_addr_n_plus_1 = key_for_addr_n.derive(path_segment_for_plus1.c_str());
            if(!key_for_addr_n_plus_1.isValid()){errorMessage=dL+" Addr+1 KeyMat Fail"; displayErrorScreen(errorMessage);goto end_wallet_view_logic;}

            String path_segment_for_plus2 = ""; 
            for (int l_p2 = 0; l_p2 < 4; l_p2++) { uint32_t index = deriveIndex(String(password), l_p2); path_segment_for_plus2 += (l_p2 > 0 ? "/" : "") + String(index) + "'"; }
            HDPrivateKey key_for_addr_n_plus_2 = key_for_addr_n_plus_1.derive(path_segment_for_plus2.c_str()); 
            if(!key_for_addr_n_plus_2.isValid()){errorMessage=dL+" Addr+2 KeyMat Fail"; displayErrorScreen(errorMessage);goto end_wallet_view_logic;}

            String addr_n_str, wif_n_str, addr_n_plus_1_str, addr_n_plus_2_str;

            if(isEvmChainFormat) {
                addr_n_str = getEvmAddress(key_for_addr_n);
                addr_n_plus_1_str = getEvmAddress(key_for_addr_n_plus_1);
                addr_n_plus_2_str = getEvmAddress(key_for_addr_n_plus_2);
            } else { 
                PublicKey pk0 = key_for_addr_n.publicKey(); pk0.compressed = true; addr_n_str = pk0.address(&Mainnet);
                PublicKey pk1 = key_for_addr_n_plus_1.publicKey(); pk1.compressed = true; addr_n_plus_1_str = pk1.address(&Mainnet);
                PublicKey pk2 = key_for_addr_n_plus_2.publicKey(); pk2.compressed = true; addr_n_plus_2_str = pk2.address(&Mainnet);
            }
            wif_n_str = key_for_addr_n.wif(); 

            bool derivation_ok = true; String error_msg_detail = "";
            if (addr_n_str.length() == 0 || (isEvmChainFormat && addr_n_str.startsWith("EVM Addr Error"))) { error_msg_detail = "Addr_n Gen Fail"; derivation_ok = false; }
            if (derivation_ok && wif_n_str.length() == 0) { error_msg_detail = "WIF_n Gen Fail"; derivation_ok = false; }
            if (derivation_ok && (addr_n_plus_1_str.length() == 0 || (isEvmChainFormat && addr_n_plus_1_str.startsWith("EVM Addr Error")))) { error_msg_detail = "Addr_n+1 Gen Fail"; derivation_ok = false; }
            if (derivation_ok && (addr_n_plus_2_str.length() == 0 || (isEvmChainFormat && addr_n_plus_2_str.startsWith("EVM Addr Error")))) { error_msg_detail = "Addr_n+2 Gen Fail"; derivation_ok = false; }

            String qrD_content = "";
            if(derivation_ok){
                qrD_content = addr_n_str + "|" + wif_n_str + "|" + addr_n_plus_1_str + "|" + addr_n_plus_2_str;
            } else {
                displayErrorScreen(error_msg_detail.length() > 0 ? error_msg_detail : dL + " Deriv QR Error");
                goto end_wallet_view_logic;
            }
             
            if(qrD_content.length()>0 && currentState==STATE_WALLET_VIEW) {
                displaySingleRotationQR(currentRotationIndex,qrD_content,dL,eQV);
            } else if (currentState==STATE_WALLET_VIEW) { 
                displayErrorScreen(dL + " QR Data Empty");
            }
        }
        end_wallet_view_logic:; break;
      } 
    case STATE_SHOW_SECRET_MNEMONIC: if(buttonLeftTriggered){ Serial.println("L: Exit Secret"); currentState = lastWalletState;} break;
    case STATE_ERROR: if(buttonLeftTriggered){ Serial.println("L: Err Ack"); currentState=STATE_CHAIN_SELECTION; currentDigitIndex=0; currentDigitValue=0; passwordConfirmed=false; memset(password,'_',PIN_LENGTH); password[PIN_LENGTH]='\0'; currentRotationIndex=0; } break;
    default: errorMessage="Unknown State"; displayErrorScreen(errorMessage); break;
  }
  delay(20); 
}
