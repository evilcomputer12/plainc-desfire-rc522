#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "RC522.h"

/*
 * Function Name: RC522_SPI_Transfer
 * Description: A common function used by Write_MFRC522 and Read_MFRC522
 * Input Parameters: data - the value to be written
 * Returns: a byte of data read from the module
 */
uint8_t RC522_SPI_Transfer(uchar data)
{
	uchar rx_data;
	HAL_SPI_TransmitReceive(HSPI_INSTANCE,&data,&rx_data,1,100);

	return rx_data;
}

/*
 * Function Name: Write_MFRC522
 * Function Description: To a certain MFRC522 register to write a byte of data
 * Input Parameters: addr - register address; val - the value to be written
 * Return value: None
 */
void Write_MFRC522(uchar addr, uchar val)
{
	/* CS LOW */
	HAL_GPIO_WritePin(MFRC522_CS_PORT,MFRC522_CS_PIN,GPIO_PIN_RESET);

	  // even though we are calling transfer frame once, we are really sending
	  // two 8-bit frames smooshed together-- sending two 8 bit frames back to back
	  // results in a spike in the select line which will jack with transactions
	  // - top 8 bits are the address. Per the spec, we shift the address left
	  //   1 bit, clear the LSb, and clear the MSb to indicate a write
	  // - bottom 8 bits are the data bits being sent for that address, we send them
	RC522_SPI_Transfer((addr<<1)&0x7E);	
	RC522_SPI_Transfer(val);
	
	/* CS HIGH */
	HAL_GPIO_WritePin(MFRC522_CS_PORT,MFRC522_CS_PIN,GPIO_PIN_SET);
}

#ifdef __GNUC__
int __io_putchar(int ch)
{
  if (ch == '\n') {
    HAL_UART_Transmit(&huart2, (uint8_t *)"\r", 1, HAL_MAX_DELAY);
  }
  HAL_UART_Transmit(&huart2, (uint8_t *)&ch, 1, HAL_MAX_DELAY);
  return ch;
}

/* ── Interrupt-driven receive ring buffer ───────────────────────────────
 * HAL_UART_Receive_IT arms a 1-byte transfer.  The RXNE ISR fires for
 * every incoming byte, stores it in the ring, and immediately re-arms.
 * __io_getchar spin-waits on the ring, so it never calls HAL_UART_Receive
 * in blocking mode and can never lose bytes to ORE during paste or while
 * the main loop is busy printing / doing SPI.
 * ─────────────────────────────────────────────────────────────────────── */
#define UART_RX_RING_SIZE 256u

static uint8_t           g_rx_ring[UART_RX_RING_SIZE];
static volatile uint16_t g_rx_head = 0;   /* written by ISR  */
static volatile uint16_t g_rx_tail = 0;   /* read by main    */
static uint8_t           g_rx_it_byte = 0;

void uart_rx_start(void)
{
  HAL_NVIC_SetPriority(USART2_IRQn, 0, 0);
  HAL_NVIC_EnableIRQ(USART2_IRQn);
  HAL_UART_Receive_IT(&huart2, &g_rx_it_byte, 1);
}

void HAL_UART_RxCpltCallback(UART_HandleTypeDef *huart)
{
  if (huart->Instance != USART2) return;
  uint16_t next = (g_rx_head + 1u) % UART_RX_RING_SIZE;
  if (next != g_rx_tail) {          /* drop silently only if ring is full */
    g_rx_ring[g_rx_head] = g_rx_it_byte;
    g_rx_head = next;
  }
  HAL_UART_Receive_IT(&huart2, &g_rx_it_byte, 1);
}

/* When ORE/framing errors occur the HAL disables the RXNE interrupt and
 * returns without calling RxCpltCallback, so the ring buffer ISR goes
 * silent and __io_getchar spins forever.  Re-arm here to recover. */
void HAL_UART_ErrorCallback(UART_HandleTypeDef *huart)
{
  if (huart->Instance != USART2) return;
  huart->ErrorCode = HAL_UART_ERROR_NONE;
  HAL_UART_Receive_IT(&huart2, &g_rx_it_byte, 1);
}

int __io_getchar(void)
{
  static int skip_lf = 0;
  while (1) {
    while (g_rx_head == g_rx_tail) {}    /* spin until a byte is available */
    uint8_t ch = g_rx_ring[g_rx_tail];
    g_rx_tail = (g_rx_tail + 1u) % UART_RX_RING_SIZE;

    if (ch == '\0') continue;
    if (skip_lf && ch == '\n') { skip_lf = 0; continue; }
    if (ch == '\r') { skip_lf = 1; return '\n'; }
    skip_lf = 0;
    return ch;
  }
}
#endif /* __GNUC__ */

int _write(int file, char *ptr, int len)
{
  (void)file;
  const uint8_t cr = '\r';
  for (int i = 0; i < len; i++) {
    if ((uint8_t)ptr[i] == '\n')
      HAL_UART_Transmit(&huart2, &cr, 1, HAL_MAX_DELAY);
    HAL_UART_Transmit(&huart2, (uint8_t *)&ptr[i], 1, HAL_MAX_DELAY);
  }
  return len;
}

/*
 * Function Name: Read_MFRC522
 * Description: From a certain MFRC522 read a byte of data register
 * Input Parameters: addr - register address
 * Returns: a byte of data read from the module
 */
uchar Read_MFRC522(uchar addr)
{
	uchar val;

	/* CS LOW */
	HAL_GPIO_WritePin(MFRC522_CS_PORT,MFRC522_CS_PIN,GPIO_PIN_RESET);

	  // even though we are calling transfer frame once, we are really sending
	  // two 8-bit frames smooshed together-- sending two 8 bit frames back to back
	  // results in a spike in the select line which will jack with transactions
	  // - top 8 bits are the address. Per the spec, we shift the address left
	  //   1 bit, clear the LSb, and set the MSb to indicate a read
	  // - bottom 8 bits are all 0s on a read per 8.1.2.1 Table 6
	RC522_SPI_Transfer(((addr<<1)&0x7E) | 0x80);	
	val = RC522_SPI_Transfer(0x00);
	
	/* CS HIGH */
	HAL_GPIO_WritePin(MFRC522_CS_PORT,MFRC522_CS_PIN,GPIO_PIN_SET);
	
	return val;	
	
}

/*
 * Function Name: SetBitMask
 * Description: Set RC522 register bit
 * Input parameters: reg - register address; mask - set value
 * Return value: None
 */
void SetBitMask(uchar reg, uchar mask)  
{
    uchar tmp;
    tmp = Read_MFRC522(reg);
    Write_MFRC522(reg, tmp | mask);  // set bit mask
}

/*
 * Function Name: ClearBitMask
 * Description: clear RC522 register bit
 * Input parameters: reg - register address; mask - clear bit value
 * Return value: None
*/
void ClearBitMask(uchar reg, uchar mask)  
{
    uchar tmp;
    tmp = Read_MFRC522(reg);
    Write_MFRC522(reg, tmp & (~mask));  // clear bit mask
} 

/*
 * Function Name: AntennaOn
 * Description: Open antennas, each time you start or shut down the natural barrier between the transmitter should be at least 1ms interval
 * Input: None
 * Return value: None
 */
void AntennaOn(void)
{

	Read_MFRC522(TxControlReg);
	SetBitMask(TxControlReg, 0x03);
}

/*
  * Function Name: AntennaOff
  * Description: Close antennas, each time you start or shut down the natural barrier between the transmitter should be at least 1ms interval
  * Input: None
  * Return value: None
 */
void AntennaOff(void)
{
	ClearBitMask(TxControlReg, 0x03);
}

/*
 * Function Name: MFRC522_Reset
 * Description: Reset RC522
 * Input: None
 * Return value: None
 */
void MFRC522_Reset(void)
{
    Write_MFRC522(CommandReg, PCD_RESETPHASE);
}

/*
 * Function Name: MFRC522_Init
 * Description: Initialize RC522
 * Input: None
 * Return value: None
*/
void MFRC522_Init(void)
{
	HAL_GPIO_WritePin(MFRC522_CS_PORT,MFRC522_CS_PIN,GPIO_PIN_SET);
	HAL_GPIO_WritePin(MFRC522_RST_PORT,MFRC522_RST_PIN,GPIO_PIN_SET);
	MFRC522_Reset();
	 	
	/* Timer: f_timer = 13.56 MHz / (TPrescaler*2+1)
	 * TPrescaler = 0x0D3E = 3390 → f_timer ≈ 2 kHz → 0.5 ms/tick
	 * TReload = 600 → timeout = 601 * 0.5 ms ≈ 300 ms
	 * DESFire NV-write operations (CreateApp, ChangeKey, WriteData)
	 * can take 50–100 ms; 15 ms was too short. */
	Write_MFRC522(TModeReg, 0x8D);
	Write_MFRC522(TPrescalerReg, 0x3E);
	Write_MFRC522(TReloadRegH, 2);          /* TReload = 2*256+88 = 600 */
	Write_MFRC522(TReloadRegL, 88);
	
	Write_MFRC522(TxAutoReg, 0x40);		// force 100% ASK modulation
	Write_MFRC522(ModeReg, 0x3D);		// CRC Initial value 0x6363
	Write_MFRC522(RFCfgReg, 0x08);		// lower RX gain, less aggressive field coupling

	AntennaOn();

	printf("[RC522] init: VersionReg=%02X TxControlReg=%02X RFCfgReg=%02X\n",
	       Read_MFRC522(VersionReg),
	       Read_MFRC522(TxControlReg),
	       Read_MFRC522(RFCfgReg));
}

/*
 * Function Name: MFRC522_ToCard
 * Description: RC522 and ISO14443 card communication
 * Input Parameters: command - MF522 command word,
 *			 sendData--RC522 sent to the card by the data
 *			 sendLen--Length of data sent
 *			 backData--Received the card returns data,
 *			 backLen--Return data bit length
 * Return value: the successful return MI_OK
 */
uchar MFRC522_ToCard(uchar command, uchar *sendData, uchar sendLen, uchar *backData, uint *backLen)
{
    uchar status = MI_ERR;
    uchar irqEn = 0x00;
    uchar waitIRq = 0x00;
    uchar lastBits;
    uchar n;
    uint i;

    switch (command)
    {
        case PCD_AUTHENT:		// Certification cards close
		{
			irqEn = 0x12;
			waitIRq = 0x10;
			break;
		}
		case PCD_TRANSCEIVE:	// Transmit FIFO data
		{
			irqEn = 0x77;
			waitIRq = 0x30;   /* RxIRq | IdleIRq — see post-wait idle drain below */
			break;
		}
		default:
			break;
    }
   
    Write_MFRC522(CommIEnReg, irqEn|0x80);	// Interrupt request
    ClearBitMask(CommIrqReg, 0x80);			// Clear all interrupt request bit
    SetBitMask(FIFOLevelReg, 0x80);			// FlushBuffer=1, FIFO Initialization
    
	Write_MFRC522(CommandReg, PCD_IDLE);	// NO action; Cancel the current command

	// Writing data to the FIFO
    for (i=0; i<sendLen; i++)
    {   
		Write_MFRC522(FIFODataReg, sendData[i]);    
	}

    // Execute the command
	Write_MFRC522(CommandReg, command);
    if (command == PCD_TRANSCEIVE)
    {    
		SetBitMask(BitFramingReg, 0x80);		// StartSend=1,transmission of data starts
	}   
    
    /* Software backstop — must be >> hardware timer so the hardware timer
     * always fires first.  At ~4 µs/iteration, 2 000 000 ≈ 8 s > 2 s timer. */
	i = 2000000;
    do
    {
		//CommIrqReg[7..0]
		//Set1 TxIRq RxIRq IdleIRq HiAlerIRq LoAlertIRq ErrIRq TimerIRq
        n = Read_MFRC522(CommIrqReg);
        i--;
    }
    while ((i!=0) && !(n&0x01) && !(n&waitIRq));

    ClearBitMask(BitFramingReg, 0x80);			//StartSend=0
	
    if (i != 0)
    {    
        if(!(Read_MFRC522(ErrorReg) & 0x1B))	//BufferOvfl Collerr CRCErr ProtecolErr
        {
            status = MI_OK;
            if (n & irqEn & 0x01)
            {   
				status = MI_NOTAGERR;
			}

            if (command == PCD_TRANSCEIVE)
            {
               	n = Read_MFRC522(FIFOLevelReg);
              	lastBits = Read_MFRC522(ControlReg) & 0x07;
                if (lastBits)
                {   
					*backLen = (n-1)*8 + lastBits;   
				}
                else
                {   
					*backLen = n*8;   
				}

                if (n == 0)
                {   
					n = 1;    
				}
                {
					uchar read_max = MFRC522_FIFO_READ_MAX;
					if (n > read_max) {
						n = read_max;
					}
				}

                // Reading the received data in FIFO
                for (i=0; i<n; i++)
                {   
					backData[i] = Read_MFRC522(FIFODataReg);    
				}
            }
        }
        else
        {   
			status = MI_ERR;  
		}
        
    }
	
    //SetBitMask(ControlReg,0x80);           //timer stops
    //Write_MFRC522(CommandReg, PCD_IDLE); 

    return status;
}

/*
 * Function Name: MFRC522_Request
 * Description: Find cards, read the card type number
 * Input parameters: reqMode - find cards way
 *   TagType - Return Card Type
 *    0x4400 = Mifare_UltraLight
 *    0x0400 = Mifare_One(S50)
 *    0x0200 = Mifare_One(S70)
 *    0x0800 = Mifare_Pro(X)
 *    0x4403 = Mifare_DESFire
 * Return value: the successful return MI_OK
 */
uchar MFRC522_Request(uchar reqMode, uchar *TagType)
{
	uchar status;  
	uint backBits;			 // The received data bits

	Write_MFRC522(BitFramingReg, 0x07);		//TxLastBists = BitFramingReg[2..0]
	
	TagType[0] = reqMode;
	status = MFRC522_ToCard(PCD_TRANSCEIVE, TagType, 1, TagType, &backBits);

	if ((status != MI_OK) || (backBits != 0x10))
	{    
		status = MI_ERR;
	}
   
	return status;
}

/*
 * Function Name: MFRC522_Anticoll
 * Description: Anti-collision detection, reading selected card serial number card
 * Input parameters: serNum - returns 4 bytes card serial number, the first 5 bytes for the checksum byte
 * Return value: the successful return MI_OK
 */
uchar MFRC522_AnticollCascade(uchar selCode, uchar *serNum)
{
    uchar status;
    uchar i;
	uchar serNumCheck=0;
    uint unLen;
    
	Write_MFRC522(BitFramingReg, 0x00);		//TxLastBists = BitFramingReg[2..0]
 
    serNum[0] = selCode;
    serNum[1] = 0x20;
    status = MFRC522_ToCard(PCD_TRANSCEIVE, serNum, 2, serNum, &unLen);

    if (status == MI_OK)
	{
    	 //Check card serial number
		for (i=0; i<4; i++)
		{   
		 	serNumCheck ^= serNum[i];
		}
		if (serNumCheck != serNum[i])
		{   
			status = MI_ERR;    
		}
    }

    return status;
} 

uchar MFRC522_Anticoll(uchar *serNum)
{
    return MFRC522_AnticollCascade(PICC_ANTICOLL, serNum);
}

/*
 * Function Name: CalulateCRC
 * Description: CRC calculation with MF522
 * Input parameters: pIndata - To read the CRC data, len - the data length, pOutData - CRC calculation results
 * Return value: None
 */
void CalulateCRC(uchar *pIndata, uchar len, uchar *pOutData)
{
    uchar i, n;

    Write_MFRC522(CommandReg, PCD_IDLE);
    ClearBitMask(DivIrqReg, 0x04);			//CRCIrq = 0
    SetBitMask(FIFOLevelReg, 0x80);			//Clear the FIFO pointer

    //Writing data to the FIFO
    for (i=0; i<len; i++)
    {   
		Write_MFRC522(FIFODataReg, *(pIndata+i));   
	}
    Write_MFRC522(CommandReg, PCD_CALCCRC);

    //Wait CRC calculation is complete
    i = 0xFF;
    do 
    {
        n = Read_MFRC522(DivIrqReg);
        i--;
    }
    while ((i!=0) && !(n&0x04));			//CRCIrq = 1

    //Read CRC calculation result
    pOutData[0] = Read_MFRC522(CRCResultRegL);
    pOutData[1] = Read_MFRC522(CRCResultRegH);
}

/*
 * Function Name: MFRC522_SelectTag
 * Description: election card, read the card memory capacity
 * Input parameters: serNum - Incoming card serial number
 * Return value: the successful return of card capacity
 */
uchar MFRC522_SelectTagCascade(uchar selCode, uchar *serNum)
{
	uchar i;
	uchar status;
	uchar size;
	uint recvBits;
	uchar buffer[9]; 

	//ClearBitMask(Status2Reg, 0x08);			//MFCrypto1On=0

    buffer[0] = selCode;
    buffer[1] = 0x70;
    for (i=0; i<5; i++)
    {
    	buffer[i+2] = *(serNum+i);
    }
	CalulateCRC(buffer, 7, &buffer[7]);
    status = MFRC522_ToCard(PCD_TRANSCEIVE, buffer, 9, buffer, &recvBits);
    
    if ((status == MI_OK) && (recvBits == 0x18))
    {   
		size = buffer[0]; 
	}
    else
    {   
		size = 0;    
	}

    return size;
}

uchar MFRC522_SelectTag(uchar *serNum)
{
    return MFRC522_SelectTagCascade(PICC_SElECTTAG, serNum);
}

/*
 * Function Name: MFRC522_Auth
 * Description: Verify card password
 * Input parameters: authMode - Password Authentication Mode
                 0x60 = A key authentication
                 0x61 = Authentication Key B
             BlockAddr--Block address
             Sectorkey--Sector password
             serNum--Card serial number, 4-byte
 * Return value: the successful return MI_OK
 */
uchar MFRC522_Auth(uchar authMode, uchar BlockAddr, uchar *Sectorkey, uchar *serNum)
{
    uchar status;
    uint recvBits;
    uchar i;
	uchar buff[12]; 

	//Verify the command block address + sector + password + card serial number
    buff[0] = authMode;
    buff[1] = BlockAddr;
    for (i=0; i<6; i++)
    {    
		buff[i+2] = *(Sectorkey+i);   
	}
    for (i=0; i<4; i++)
    {    
		buff[i+8] = *(serNum+i);   
	}
    status = MFRC522_ToCard(PCD_AUTHENT, buff, 12, buff, &recvBits);

    if ((status != MI_OK) || (!(Read_MFRC522(Status2Reg) & 0x08)))
    {   
		status = MI_ERR;   
	}
    
    return status;
}

/*
 * Function Name: MFRC522_Read
 * Description: Read block data
 * Input parameters: blockAddr - block address; recvData - read block data
 * Return value: the successful return MI_OK
 */
uchar MFRC522_Read(uchar blockAddr, uchar *recvData)
{
    uchar status;
    uint unLen;

    recvData[0] = PICC_READ;
    recvData[1] = blockAddr;
    CalulateCRC(recvData,2, &recvData[2]);
    status = MFRC522_ToCard(PCD_TRANSCEIVE, recvData, 4, recvData, &unLen);

    if ((status != MI_OK) || (unLen != 0x90))
    {
        status = MI_ERR;
    }
    
    return status;
}

/*
 * Function Name: MFRC522_Write
 * Description: Write block data
 * Input parameters: blockAddr - block address; writeData - to 16-byte data block write
 * Return value: the successful return MI_OK
 */
uchar MFRC522_Write(uchar blockAddr, uchar *writeData)
{
    uchar status;
    uint recvBits;
    uchar i;
	uchar buff[18]; 
    
    buff[0] = PICC_WRITE;
    buff[1] = blockAddr;
    CalulateCRC(buff, 2, &buff[2]);
    status = MFRC522_ToCard(PCD_TRANSCEIVE, buff, 4, buff, &recvBits);

    if ((status != MI_OK) || (recvBits != 4) || ((buff[0] & 0x0F) != 0x0A))
    {   
		status = MI_ERR;   
	}
        
    if (status == MI_OK)
    {
        for (i=0; i<16; i++)		//Data to the FIFO write 16Byte
        {    
        	buff[i] = *(writeData+i);   
        }
        CalulateCRC(buff, 16, &buff[16]);
        status = MFRC522_ToCard(PCD_TRANSCEIVE, buff, 18, buff, &recvBits);
        
		if ((status != MI_OK) || (recvBits != 4) || ((buff[0] & 0x0F) != 0x0A))
        {   
			status = MI_ERR;   
		}
    }
    
    return status;
}

/*
 * Function Name: MFRC522_Halt
 * Description: Command card into hibernation
 * Input: None
 * Return value: None
 */
void MFRC522_Halt(void)
{
	uint unLen;
	uchar buff[4]; 

	buff[0] = PICC_HALT;
	buff[1] = 0;
	CalulateCRC(buff, 2, &buff[2]);
 
	MFRC522_ToCard(PCD_TRANSCEIVE, buff, 4, buff,&unLen);
}

static uint8_t pcb = 0x02;

#ifndef RC522_VERBOSE
#define RC522_VERBOSE 1
#endif

#if RC522_VERBOSE
#define MFRC522_PRINTF printf
#else
#define MFRC522_PRINTF(...) do { } while (0)
#endif

/* Always-on ISO14443-4 summary (serial); hex detail uses RC522_VERBOSE. */
#define P4_LOG(...) printf("[P4] " __VA_ARGS__)

void MFRC522_DumpRegs(const char *tag)
{
	printf("[RC522] %s: CMD=%02X IRQ=%02X ERR=%02X S1=%02X S2=%02X FIFO=%02X RF=%02X\n",
	       tag ? tag : "?",
	       Read_MFRC522(CommandReg),
	       Read_MFRC522(CommIrqReg),
	       Read_MFRC522(ErrorReg),
	       Read_MFRC522(Status1Reg),
	       Read_MFRC522(Status2Reg),
	       Read_MFRC522(FIFOLevelReg),
	       Read_MFRC522(RFCfgReg));
}

static const char *p4_pcb_kind(uint8_t pcb)
{
	if (PHPAL_I14443P4_SW_IS_I_BLOCK(pcb) > 0U) return "I";
	if (PHPAL_I14443P4_SW_IS_R_BLOCK(pcb) > 0U) {
		return (PHPAL_I14443P4_SW_IS_ACK(pcb) > 0U) ? "R-ACK" : "R-NAK";
	}
	if (PHPAL_I14443P4_SW_IS_S_BLOCK(pcb) > 0U) {
		if (PHPAL_I14443P4_SW_IS_WTX(pcb) > 0U) return "S-WTX";
		if (PHPAL_I14443P4_SW_IS_DESELECT(pcb) > 0U) return "S-DESEL";
		return "S";
	}
	return "?";
}

static void print_block(uint8_t * block, uint8_t length){
    for (uint8_t i=0; i<length; i++){
    	MFRC522_PRINTF("%02X ", block[i]);
    }
    MFRC522_PRINTF("\n");
}

uint8_t res[256];
uint resSize = sizeof(res);

/* PICC frame size from ATS (ISO 14443-4 Table 5). Updated after RATS. */
static uint16_t g_iso_fsc = 64;
/* Keep ChangeKey chained, but let 37/38-byte WriteData/Auth frames stay single. */
#define MFRC522_P4_MAX_INF_TX 40u

uint16_t MFRC522_GetIsoFsc(void)
{
	return g_iso_fsc;
}

static uint16_t iso_fsci_to_fsc(uint8_t fsci)
{
	static const uint16_t fsc_table[] = {
		16, 24, 32, 40, 48, 64, 96, 128, 256
	};
	if (fsci >= (sizeof(fsc_table) / sizeof(fsc_table[0]))) {
		return 256;
	}
	return fsc_table[fsci];
}

/* Default TPrescaler/TReload from MFRC522_Init (~300 ms hardware timeout). */
static void MFRC522_RestoreRfTimer(void)
{
	Write_MFRC522(TReloadRegH, 2);
	Write_MFRC522(TReloadRegL, 88);
}

/* Extended timeout for DESFire NV writes (ChangeKey, CreateApp, Format, …). */
static void MFRC522_SetNvWriteTimer(void)
{
	Write_MFRC522(TReloadRegH, 15);   /* TReload = 15*256+159 = 3999 */
	Write_MFRC522(TReloadRegL, 159);  /* timeout ≈ 4000 * 0.5 ms = 2 s   */
}

/* ISO14443-4: wait for RX data and for FIFO level to stabilize (long NV replies). */
static void p4_wait_rx_complete(void)
{
	uint32_t t0 = HAL_GetTick();
	uint8_t prev = 0xFFu;

	while ((HAL_GetTick() - t0) < 3000u) {
		uint8_t lvl = Read_MFRC522(FIFOLevelReg);
		if (lvl > 0u) {
			if (lvl == prev) {
				HAL_Delay(1);
				if (Read_MFRC522(FIFOLevelReg) == lvl) {
					return;
				}
			}
			prev = lvl;
		}
		HAL_Delay(1);
	}
}

/* Read full RX from FIFO after ToCard (which only copies the first MAX_LEN bytes). */
static void p4_read_rx_fifo(uint8_t *rx, uint32_t *rxBytes)
{
	uint8_t leftover = Read_MFRC522(FIFOLevelReg);
	while (leftover-- > 0u && *rxBytes < 256u) {
		rx[(*rxBytes)++] = Read_MFRC522(FIFODataReg);
	}
}

/* Trim RX to a valid ISO14443-3 CRC frame (handles FIFO overrun). */
static uint32_t p4_frame_len_by_crc(const uint8_t *rx, uint32_t rx_len)
{
	if (rx_len < 4u) {
		return rx_len;
	}

	/* Encrypted DESFire payload can accidentally contain a shorter prefix whose
	 * trailing bytes match a CRC. Prefer the longest valid frame, not the first.
	 */
	for (uint32_t end = rx_len; end >= 4u; end--) {
		uint8_t crc[2];
		CalulateCRC((uchar *)rx, (uint8_t)(end - 2u), crc);
		if (rx[end - 2u] == crc[0] && rx[end - 1u] == crc[1]) {
			return end;
		}
		if (end == 4u) {
			break;
		}
	}
	return rx_len;
}

/* INF offset/length inside PCB|INF|CRC frame. */
static size_t p4_inf_field(const uint8_t *frame, uint32_t frame_len, size_t *inf_off)
{
	*inf_off = 1u;
	if (frame_len < 3u) {
		return 0u;
	}
	size_t inf_len = (size_t)frame_len - 3u;
	if ((frame[0] & 0x08u) != 0u && inf_len > 0u) {
		*inf_off = 2u;
		inf_len--;
	}
	return inf_len;
}

/* DESFire ISO APDU in INF: payload + 0x91 SW2; drop trailing FIFO garbage.
 * Encrypted payload may contain 0x91, so select the last status marker. */
static size_t p4_desfire_inf_len(const uint8_t *inf, size_t inf_len)
{
	if (inf_len < 2u) {
		return inf_len;
	}
	for (size_t i = inf_len - 2u; i > 0u; i--) {
		if (inf[i] == 0x91u) {
			return i + 2u;
		}
	}
	if (inf[0] == 0x91u) {
		return 2u;
	}
	return inf_len;
}

static uint32_t p4_copy_inf_apdu(const uint8_t *frame, uint32_t frame_len,
                                 uint8_t *data, uint32_t data_cap)
{
	size_t inf_off = 0;
	size_t inf_len = p4_inf_field(frame, frame_len, &inf_off);
	if (inf_len == 0u) {
		return 0u;
	}
	inf_len = p4_desfire_inf_len(frame + inf_off, inf_len);
	size_t copy = (inf_len < (size_t)data_cap) ? inf_len : (size_t)data_cap;
	memcpy(data, frame + inf_off, copy);
	return (uint32_t)copy;
}

uint8_t MFRC522_RATS(void)
{
	/* ISO/IEC 14443-4 activation:
	 *   RATS = 0xE0, PARAM(FSDI[7:4] | CID[3:0]).
	 * Request FSDI=8 first like the CLRC663 reference, then fall back.
	 */
	const uint8_t candidates[][2] = {
		{0xE0, 0x80},
		{0xE0, 0x50},
		{0xE0, 0x20},
	};
	const uint8_t reqSize = 4;

	for (size_t attempt = 0; attempt < (sizeof(candidates) / sizeof(candidates[0])); attempt++) {
		uint8_t req[4] = { candidates[attempt][0], candidates[attempt][1], 0x00, 0x00 };
		uint8_t status;
		uint32_t savedSize = resSize;
		uint resBits = 0;
		uint32_t resBytes = 0;

		CalulateCRC(req, 2, &req[2]);
		memset(res, 0, savedSize);

		MFRC522_PRINTF("RATS attempt %u (%ub) > ", (unsigned)(attempt + 1), reqSize);
		print_block(req, reqSize);

		status = MFRC522_ToCard(PCD_TRANSCEIVE, req, reqSize, res, &resBits);
		if (status == MI_OK) {
			p4_wait_rx_complete();
		}
		resBytes = (resBits + 7u) / 8u;
		if (status == MI_OK) {
			p4_read_rx_fifo(res, &resBytes);
		}
		P4_LOG("RATS try %u: status=%u len=%u req=%02X %02X\n",
		       (unsigned)(attempt + 1), (unsigned)status, (unsigned)resBytes,
		       candidates[attempt][0], candidates[attempt][1]);
		if (status == MI_OK && resBytes >= 2u)
		{
			uint8_t fsci = (res[1] >> 4) & 0x0Fu;
			g_iso_fsc = iso_fsci_to_fsc(fsci);
			uint32_t max_inf = (g_iso_fsc > 3u) ? (uint32_t)(g_iso_fsc - 3u) : 16u;
			P4_LOG("RATS OK: ATS len=%u FSCI=%u FSC=%u maxINF=%u (ChangeKey APDU=47 needs INF<=maxINF or chain)\n",
			       (unsigned)resBytes, (unsigned)fsci, (unsigned)g_iso_fsc, (unsigned)max_inf);
			MFRC522_PRINTF("ATS (%ub) < ", (unsigned)resBytes);
			print_block(res, (uint8_t)resBytes);
			resSize = resBytes;
			pcb = 0x02;   /* reset ISO 14443-4 block number after fresh RATS */
			return status;
		}

		MFRC522_DumpRegs("rats-fail");

		resSize = savedSize;
		HAL_Delay(50);
	}

	return MI_ERR;
}

//I-Block
static uint8_t get_pcb()
{
	uint8_t _pcb = pcb;

	if(pcb==0x02)
		pcb = 0x03;
	else
		pcb = 0x02;

	return _pcb;
}

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

/* One T=CL frame exchange. */
static uint8_t p4_exchange_frame(const uint8_t *req, uint32_t reqSize,
                                 uint8_t *rx, uint32_t *rxBytes)
{
	uint resBits = 0;

	uint8_t status = MFRC522_ToCard(PCD_TRANSCEIVE, (uchar *)req, (uchar)reqSize,
	                                rx, &resBits);
	if (status == MI_OK) {
		p4_wait_rx_complete();
	}
	*rxBytes = (resBits + 7u) / 8u;
	if (status == MI_OK) {
		p4_read_rx_fifo(rx, rxBytes);
		/* Trim only when the FIFO delivered extra bytes past a valid CRC. */
		if (*rxBytes > 8u) {
			uint32_t trimmed = p4_frame_len_by_crc(rx, *rxBytes);
			if (trimmed != *rxBytes && trimmed >= 4u) {
				P4_LOG("RX CRC trim %u -> %u\n",
				       (unsigned)*rxBytes, (unsigned)trimmed);
				*rxBytes = trimmed;
			} else if ((Read_MFRC522(Status2Reg) & 0x08u) == 0u) {
				P4_LOG("RX no CRC trim match len=%u Status2=%02X\n",
				       (unsigned)*rxBytes, (unsigned)Read_MFRC522(Status2Reg));
			}
		}
	}
	return status;
}

/* Handle PICC I-block (APDU response) or S(WTX) after the final command block. */
static uint8_t p4_recv_apdu_response(uint8_t *req, uint32_t *reqSize,
                                     uint8_t *data, uint32_t dataSizeAlloc,
                                     uint32_t *dataSize)
{
	uint32_t retries = 24;
	uint32_t wtx_left = 32;
	uint8_t status = MI_ERR;
	uint32_t resBytes = 0;

	*dataSize = 0;

	do {
		status = p4_exchange_frame(req, *reqSize, res, &resBytes);
		if (status != MI_OK) {
			break;
		}

		MFRC522_PRINTF("14443P4 (%ub) < ", (unsigned)resBytes);
		print_block(res, (uint8_t)resBytes);

		if (PHPAL_I14443P4_SW_IS_I_BLOCK(res[PHPAL_I14443P4_SW_PCB_POS]) > 0U) {
			*dataSize = p4_copy_inf_apdu(res, resBytes, data, dataSizeAlloc);
			status = MI_OK;
			break;
		}
		if ((PHPAL_I14443P4_SW_IS_S_BLOCK(res[PHPAL_I14443P4_SW_PCB_POS]) > 0U) &&
		    (PHPAL_I14443P4_SW_IS_WTX(res[PHPAL_I14443P4_SW_PCB_POS]) > 0U)) {
			if (wtx_left-- == 0u) {
				status = MI_ERR;
				break;
			}
			uint8_t bWtxm = (resBytes >= 2u) ? res[1] : 0x01u;
			bWtxm &= 0x3Fu;
			if (bWtxm == 0u) {
				bWtxm = 0x01u;
			}
			req[0] = PHPAL_I14443P4_SW_S_BLOCK | PHPAL_I14443P4_SW_S_BLOCK_RFU_BITS |
			         PHPAL_I14443P4_SW_PCB_WTX;
			req[1] = bWtxm;
			CalulateCRC(req, 2u, &req[2]);
			*reqSize = 4;
			MFRC522_PRINTF("14443P4 S(WTX) (%ub) > ", (unsigned)*reqSize);
			print_block(req, (uint8_t)*reqSize);
			HAL_Delay((uint32_t)bWtxm * 80u);
			continue;
		}
		status = MI_ERR;
		break;
	} while (retries-- != 0u);

	return status;
}

uint8_t MFRC522_14443P4_Transceive(uint8_t cmd[], uint32_t cmdSize, uint8_t data[], uint32_t* dataSize)
{
	uint8_t req[260];
	uint32_t reqSize = 0;
	uint8_t status = MI_ERR;
	uint32_t offset = 0;
	uint32_t max_inf = (g_iso_fsc > 3u) ? (uint32_t)(g_iso_fsc - 3u) : 16u;
	const uint32_t dataSizeAlloc = sizeof(res);

	if (max_inf > MFRC522_P4_MAX_INF_TX) {
		max_inf = MFRC522_P4_MAX_INF_TX;
	}

	memset(res, 0, sizeof(res));
	*dataSize = 0;

	MFRC522_SetNvWriteTimer();

	{
		uint32_t card_max_inf = (g_iso_fsc > 3u) ? (uint32_t)(g_iso_fsc - 3u) : 16u;
		uint32_t frame_if_fit = cmdSize + 3u;
		P4_LOG("TX APDU len=%lu FSC=%u cardMaxINF=%u txMaxINF=%u single_frame=%s (TCL=%lu bytes)\n",
		       (unsigned long)cmdSize, (unsigned)g_iso_fsc, (unsigned)card_max_inf,
		       (unsigned)max_inf,
		       (cmdSize <= max_inf) ? "yes" : "no — chaining",
		       (unsigned long)frame_if_fit);
	}

	uint32_t block_num = 0;
	while (offset < cmdSize) {
		uint32_t chunk = cmdSize - offset;
		bool more = chunk > max_inf;
		block_num++;
		if (more) {
			chunk = max_inf;
		}

		uint8_t ipcb = get_pcb();
		if (more) {
			ipcb |= PHPAL_I14443P4_SW_PCB_CHAINING;
		}

		req[0] = ipcb;
		memcpy(&req[1], cmd + offset, chunk);
		CalulateCRC(req, (uint8_t)(chunk + 1u), &req[chunk + 1u]);
		reqSize = 1u + chunk + 2u;

		P4_LOG("I-block #%u: PCB=%02X frame=%u INF=%u%s offset=%lu\n",
		       (unsigned)block_num, (unsigned)ipcb,
		       (unsigned)reqSize, (unsigned)chunk, more ? " CHAIN" : " FINAL",
		       (unsigned long)offset);
		MFRC522_PRINTF("14443P4 I-block (%ub%s) > ", (unsigned)reqSize,
		               more ? ", chain" : "");
		print_block(req, (uint8_t)reqSize);

		uint32_t resBytes = 0;
		status = p4_exchange_frame(req, reqSize, res, &resBytes);
		if (status != MI_OK) {
			P4_LOG("I-block exchange failed status=%u\n", (unsigned)status);
			MFRC522_DumpRegs("p4-tx-fail");
			break;
		}

		P4_LOG("RX frame len=%u PCB=%02X type=%s\n",
		       (unsigned)resBytes,
		       resBytes > 0u ? (unsigned)res[0] : 0u,
		       resBytes > 0u ? p4_pcb_kind(res[0]) : "none");
		MFRC522_PRINTF("14443P4 (%ub) < ", (unsigned)resBytes);
		print_block(res, (uint8_t)resBytes);

		if (more) {
			if ((PHPAL_I14443P4_SW_IS_R_BLOCK(res[PHPAL_I14443P4_SW_PCB_POS]) == 0U) ||
			    (PHPAL_I14443P4_SW_IS_ACK(res[PHPAL_I14443P4_SW_PCB_POS]) == 0U)) {
				P4_LOG("expected R-ACK after chain block, got %s\n",
				       resBytes > 0u ? p4_pcb_kind(res[0]) : "empty");
				status = MI_ERR;
				break;
			}
			P4_LOG("R-ACK ok, send next chain block\n");
			offset += chunk;
			continue;
		}

		/* Final command block — expect I-block response (or WTX first). */
		if (PHPAL_I14443P4_SW_IS_I_BLOCK(res[PHPAL_I14443P4_SW_PCB_POS]) > 0U) {
			*dataSize = p4_copy_inf_apdu(res, resBytes, data, dataSizeAlloc);
			status = MI_OK;
			break;
		}
		if ((PHPAL_I14443P4_SW_IS_S_BLOCK(res[PHPAL_I14443P4_SW_PCB_POS]) > 0U) &&
		    (PHPAL_I14443P4_SW_IS_WTX(res[PHPAL_I14443P4_SW_PCB_POS]) > 0U)) {
			uint8_t bWtxm = (resBytes >= 2u) ? res[1] : 0x01u;
			bWtxm &= 0x3Fu;
			if (bWtxm == 0u) {
				bWtxm = 0x01u;
			}
			req[0] = PHPAL_I14443P4_SW_S_BLOCK | PHPAL_I14443P4_SW_S_BLOCK_RFU_BITS |
			         PHPAL_I14443P4_SW_PCB_WTX;
			req[1] = bWtxm;
			CalulateCRC(req, 2u, &req[2]);
			reqSize = 4;
			HAL_Delay((uint32_t)bWtxm * 80u);
			status = p4_recv_apdu_response(req, &reqSize, data, dataSizeAlloc, dataSize);
			break;
		}
		P4_LOG("unexpected RX after final block: %s\n",
		       resBytes > 0u ? p4_pcb_kind(res[0]) : "empty");
		status = MI_ERR;
		break;
	}

	if (status != MI_OK) {
		P4_LOG("transceive failed status=%u apdu_len=%lu\n",
		       (unsigned)status, (unsigned long)cmdSize);
	} else {
		P4_LOG("transceive OK INF out=%lu\n", (unsigned long)*dataSize);
	}

	MFRC522_RestoreRfTimer();
	return status;
}

uint8_t MFRC522_14443P4_Deselect()
{
	uint8_t status = 0;

	uint8_t req[3];
	uint reqSize;

	/* S-Block PCB */
	req[PHPAL_I14443P4_SW_PCB_POS]  = PHPAL_I14443P4_SW_S_BLOCK | PHPAL_I14443P4_SW_S_BLOCK_RFU_BITS;
	req[PHPAL_I14443P4_SW_PCB_POS] |= PHPAL_I14443P4_SW_PCB_DESELECT;
	CalulateCRC(req, 1u, &req[1]);
	reqSize = 3;

	MFRC522_PRINTF("14443P4 S(DESELECT) (%ub) > ", reqSize);
	print_block(req, reqSize);

	uint8_t res[8];
	uint resSize = sizeof(res);
	memset(res, 0, resSize);

	uint resBits = 0;
	uint resBytes = 0;
	status = MFRC522_ToCard(PCD_TRANSCEIVE, req, reqSize, res, &resBits);
	resBytes = (resBits + 7u) / 8u;
	if(status == MI_OK)
	{
		MFRC522_PRINTF("14443P4 (%ub) < ", (unsigned)resBytes);
		print_block(res, (uint8_t)resBytes);
	}

	return status;
}

void MFRC522_FieldReset(uint32_t off_ms)
{
	if (off_ms < 5u) {
		off_ms = 5u;
	}

	Write_MFRC522(CommandReg, PCD_IDLE);
	SetBitMask(FIFOLevelReg, 0x80);
	ClearBitMask(Status2Reg, 0x08);
	MFRC522_RestoreRfTimer();

	AntennaOff();
	HAL_Delay(off_ms);
	AntennaOn();
	HAL_Delay(2);

	pcb = 0x02;
	g_iso_fsc = 64;
}
