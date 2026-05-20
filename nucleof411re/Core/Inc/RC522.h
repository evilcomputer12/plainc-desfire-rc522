#include "stm32f4xx_hal.h"

extern UART_HandleTypeDef huart2;

#ifdef __GNUC__
  /* With GCC/STM32CubeIDE, printf calls __io_putchar() */
  int __io_putchar(int ch);
#else
  int fputc(int ch, FILE *f);
#endif /* __GNUC__ */

int _write(int file, char *ptr, int len);
void uart_rx_start(void);  /* arm interrupt-driven receive; call once after UART init */

#define	uchar	unsigned char
#define	uint	unsigned int
extern SPI_HandleTypeDef hspi1;

// UID / anticollision buffers
#define MAX_LEN 16
/* Max bytes read from RX FIFO in one transceive (ISO14443-4 frames). */
#define MFRC522_FIFO_READ_MAX 64

#define HSPI_INSTANCE				&hspi1
/*
 * CubeMX pin map for this project:
 *   PA5 -> SPI1_SCK
 *   PA6 -> SPI1_MISO
 *   PA7 -> SPI1_MOSI
 *   PA8 -> RC522 CS / NSS
 *   PB9 -> RC522 RST
 *
 * If your board is wired differently, change these two macros to match.
 */
#define MFRC522_CS_PORT				GPIOA
#define MFRC522_CS_PIN				GPIO_PIN_8
#define MFRC522_RST_PORT			GPIOB
#define MFRC522_RST_PIN				GPIO_PIN_9

// MFRC522 commands. Described in chapter 10 of the datasheet.
#define PCD_IDLE              0x00               // no action, cancels current command execution
#define PCD_AUTHENT           0x0E               // performs the MIFARE standard authentication as a reader
#define PCD_RECEIVE           0x08               // activates the receiver circuits
#define PCD_TRANSMIT          0x04               // transmits data from the FIFO buffer
#define PCD_TRANSCEIVE        0x0C               // transmits data from FIFO buffer to antenna and automatically activates the receiver after transmission
#define PCD_RESETPHASE        0x0F               // resets the MFRC522
#define PCD_CALCCRC           0x03               // activates the CRC coprocessor or performs a self-test

// Commands sent to the PICC.
#define PICC_REQIDL           0x26               // REQuest command, Type A. Invites PICCs in state IDLE to go to READY and prepare for anticollision or selection. 7 bit frame.
#define PICC_REQALL           0x52               // Wake-UP command, Type A. Invites PICCs in state IDLE and HALT to go to READY(*) and prepare for anticollision or selection. 7 bit frame.
#define PICC_ANTICOLL         0x93               // Anti collision/Select, Cascade Level 1
#define PICC_ANTICOLL2        0x95               // Anti collision/Select, Cascade Level 2
#define PICC_SElECTTAG        0x93               // Anti collision/Select, Cascade Level 2
#define PICC_SElECTTAG2       0x95               // Anti collision/Select, Cascade Level 2
#define PICC_AUTHENT1A        0x60               // Perform authentication with Key A
#define PICC_AUTHENT1B        0x61               // Perform authentication with Key B
#define PICC_READ             0x30               // Reads one 16 byte block from the authenticated sector of the PICC. Also used for MIFARE Ultralight.
#define PICC_WRITE            0xA0               // Writes one 16 byte block to the authenticated sector of the PICC. Called "COMPATIBILITY WRITE" for MIFARE Ultralight.
#define PICC_DECREMENT        0xC0               // Decrements the contents of a block and stores the result in the internal data register.
#define PICC_INCREMENT        0xC1               // Increments the contents of a block and stores the result in the internal data register
#define PICC_RESTORE          0xC2               // Reads the contents of a block into the internal data register.
#define PICC_TRANSFER         0xB0               // Writes the contents of the internal data register to a block.
#define PICC_HALT             0x50               // HaLT command, Type A. Instructs an ACTIVE PICC to go to state HALT.


// Success or error code is returned when communication
#define MI_OK                 0
#define MI_NOTAGERR           1
#define MI_ERR                2


// MFRC522 registers. Described in chapter 9 of the datasheet.
// Page 0: Command and Status
#define     Reserved00            0x00
#define     CommandReg            0x01
#define     CommIEnReg            0x02
#define     DivlEnReg             0x03
#define     CommIrqReg            0x04
#define     DivIrqReg             0x05
#define     ErrorReg              0x06
#define     Status1Reg            0x07
#define     Status2Reg            0x08
#define     FIFODataReg           0x09
#define     FIFOLevelReg          0x0A
#define     WaterLevelReg         0x0B
#define     ControlReg            0x0C
#define     BitFramingReg         0x0D
#define     CollReg               0x0E
#define     Reserved01            0x0F
//Page 1: Command
#define     Reserved10            0x10
#define     ModeReg               0x11
#define     TxModeReg             0x12
#define     RxModeReg             0x13
#define     TxControlReg          0x14
#define     TxAutoReg             0x15
#define     TxSelReg              0x16
#define     RxSelReg              0x17
#define     RxThresholdReg        0x18
#define     DemodReg              0x19
#define     Reserved11            0x1A
#define     Reserved12            0x1B
#define     MifareReg             0x1C
#define     Reserved13            0x1D
#define     Reserved14            0x1E
#define     SerialSpeedReg        0x1F
//Page 2: Configuration
#define     Reserved20            0x20
#define     CRCResultRegH         0x21
#define     CRCResultRegL         0x22
#define     Reserved21            0x23
#define     ModWidthReg           0x24
#define     Reserved22            0x25
#define     RFCfgReg              0x26
#define     GsNReg                0x27
#define     CWGsPReg	          0x28
#define     ModGsPReg             0x29
#define     TModeReg              0x2A
#define     TPrescalerReg         0x2B
#define     TReloadRegH           0x2C
#define     TReloadRegL           0x2D
#define     TCounterValueRegH     0x2E
#define     TCounterValueRegL     0x2F
//Page 3: Test Registers
#define     Reserved30            0x30
#define     TestSel1Reg           0x31
#define     TestSel2Reg           0x32
#define     TestPinEnReg          0x33
#define     TestPinValueReg       0x34
#define     TestBusReg            0x35
#define     AutoTestReg           0x36
#define     VersionReg            0x37
#define     AnalogTestReg         0x38
#define     TestDAC1Reg           0x39
#define     TestDAC2Reg           0x3A
#define     TestADCReg            0x3B
#define     Reserved31            0x3C
#define     Reserved32            0x3D
#define     Reserved33            0x3E
#define     Reserved34			  0x3F

// ISO14443-4 compatibility constants used by the extended transceive helper.
#define PHPAL_I14443P4_SW_PCB_POS        0U
#define PHPAL_I14443P4_SW_PCB_BLOCKNR    0x01U
#define PHPAL_I14443P4_SW_PCB_NAK        0x10U
#define PHPAL_I14443P4_SW_PCB_ACK        0x00U
#define PHPAL_I14443P4_SW_PCB_CHAINING   0x10U
#define PHPAL_I14443P4_SW_PCB_WTX        0x30U
#define PHPAL_I14443P4_SW_PCB_DESELECT   0x00U
#define PHPAL_I14443P4_SW_BLOCK_MASK     0xC0U
#define PHPAL_I14443P4_SW_I_BLOCK        0x00U
#define PHPAL_I14443P4_SW_R_BLOCK        0x80U
#define PHPAL_I14443P4_SW_S_BLOCK        0xC0U
#define PHPAL_I14443P4_SW_S_BLOCK_RFU_BITS 0x02U

// Functions for manipulating the MFRC522
void MFRC522_Init(void);
uchar Read_MFRC522(uchar addr);
void Write_MFRC522(uchar addr, uchar val);
uchar MFRC522_Request(uchar reqMode, uchar *TagType);
uchar MFRC522_Anticoll(uchar *serNum);
uchar MFRC522_SelectTag(uchar *serNum);
uchar MFRC522_AnticollCascade(uchar selCode, uchar *serNum);
uchar MFRC522_SelectTagCascade(uchar selCode, uchar *serNum);
uchar MFRC522_Auth(uchar authMode, uchar BlockAddr, uchar *Sectorkey, uchar *serNum);
uchar MFRC522_Write(uchar blockAddr, uchar *writeData);				
uchar MFRC522_Auth(uchar authMode, uchar BlockAddr, uchar *Sectorkey, uchar *serNum);
uchar MFRC522_Read(uchar blockAddr, uchar *recvData);
void MFRC522_Halt(void);
uint8_t MFRC522_RATS(void);
/**
 *
 * Frame Format for ISO/IEC 14443-4
 * ================================
 *
 * The frame format ISO 14443-4 specifications for block formats.
 * This is the format used by the example firmware, and seen in Figure 3.
 *  - PCB – Protocol Control Byte, this byte is used to transfer format information about each PDU block.
 *  - CID – Card Identifier field, this byte is used to identify specific tags. It contains a 4 bit CID value as well
 *          as information on the signal strength between the reader and the tag.
 *  - NAD – Node Address field, the example firmware does not support the use of NAD.
 *  - INF – Information field
 *  - EDC – CRC of the transmitted block, which is the CRC defined in ISO/IEC 14443-3
 *
 *  |-----|-----|-----|----------------|-----|
 *  | PCB | CID | NAD |      INF       | EDC |
 *  |-----|-----|-----|----------------|-----|
 *
 */
#define PHPAL_I14443P4_SW_IS_BLOCKNR_EQUAL(bPcb)                        \
    (                                                                   \
        ((((bPcb) & PHPAL_I14443P4_SW_PCB_BLOCKNR) ^ pDataParams->bPcbBlockNum) == 0U) \
        ? 1u : 0u                                                       \
    )

#define PHPAL_I14443P4_SW_IS_ACK(bPcb)                                  \
    (                                                                   \
    (((bPcb) & PHPAL_I14443P4_SW_PCB_NAK) == PHPAL_I14443P4_SW_PCB_ACK) \
    ? 1u : 0u                                                             \
    )

#define PHPAL_I14443P4_SW_IS_CHAINING(bPcb)                                         \
    (                                                                               \
    (((bPcb) & PHPAL_I14443P4_SW_PCB_CHAINING) == PHPAL_I14443P4_SW_PCB_CHAINING)   \
    ? 1u : 0u                                                                         \
    )

#define PHPAL_I14443P4_SW_IS_WTX(bPcb)                                  \
    (                                                                   \
    (((bPcb) & PHPAL_I14443P4_SW_PCB_WTX) == PHPAL_I14443P4_SW_PCB_WTX) \
    ? 1u : 0u                                                             \
    )

#define PHPAL_I14443P4_SW_IS_DESELECT(bPcb)                                     \
    (                                                                           \
    (((bPcb) & PHPAL_I14443P4_SW_PCB_WTX) == PHPAL_I14443P4_SW_PCB_DESELECT)    \
    ? 1u : 0u                                                                     \
    )

#define PHPAL_I14443P4_SW_IS_I_BLOCK(bPcb)                                  \
    (                                                                       \
    (((bPcb) & PHPAL_I14443P4_SW_BLOCK_MASK) == PHPAL_I14443P4_SW_I_BLOCK)  \
    ? 1u : 0u                                                                 \
    )

#define PHPAL_I14443P4_SW_IS_R_BLOCK(bPcb)                                  \
    (                                                                       \
    (((bPcb) & PHPAL_I14443P4_SW_BLOCK_MASK) == PHPAL_I14443P4_SW_R_BLOCK)  \
    ? 1u : 0u                                                                 \
    )

#define PHPAL_I14443P4_SW_IS_S_BLOCK(bPcb)                                  \
    (                                                                       \
    (((bPcb) & PHPAL_I14443P4_SW_BLOCK_MASK) == PHPAL_I14443P4_SW_S_BLOCK)  \
    ? 1u : 0u                                                                 \
    )

uint8_t MFRC522_14443P4_Transceive(uint8_t cmd[], uint32_t cmdSize, uint8_t data[], uint32_t* dataSize);
uint16_t MFRC522_GetIsoFsc(void);
void MFRC522_DumpRegs(const char *tag);
uint8_t MFRC522_14443P4_Deselect();
void MFRC522_FieldReset(uint32_t off_ms);
void MFRC522_Halt(void);
