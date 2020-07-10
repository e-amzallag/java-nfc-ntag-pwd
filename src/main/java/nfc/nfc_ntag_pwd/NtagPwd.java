package nfc.nfc_ntag_pwd;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.nfctools.utils.CardTerminalUtils;

/**
 * Small example to illustrate how to authenticate, set and unset a password for
 * a NTAG213 with ACS ACR122 USB terminal.<br>
 * Password is MD5-hashed and the first 4 bytes are kept (compatible with NFC
 * Tools App by wakdev).
 *
 */
public class NtagPwd {

	// 0x29 : AUTH0 address for NTAG213
	public static final byte AUTH0_ADD = (byte) 0x29;

	// 0x2B : PWD address for NTAG213
	public static final byte PWD_ADD = (byte) 0x2B;

	// 0xA2 : Write cmd for NTAG21x
	public static final byte WRITE_CMD = (byte) 0xA2;

	// 0x30 : Read cmd for NTAG21x
	public static final byte READ_CMD = (byte) 0x30;

	public static final byte[] IS_AUTH_CM = { READ_CMD, AUTH0_ADD };

	public static final byte[] AUTH_CM = { (byte) 0x1B };

	public static final byte[] SET_CONFIG_CMD = new byte[] { WRITE_CMD, AUTH0_ADD, 4, 0, 0, 0 };

	public static final byte[] SET_PWD_CMD = new byte[] { WRITE_CMD, PWD_ADD };

	public static final byte[] UNSET_CONFIG_CMD = new byte[] { WRITE_CMD, AUTH0_ADD, 4, 0, 0, (byte) 0xFF };

	public static final byte[] UNSET_PWD_CMD = new byte[] { WRITE_CMD, PWD_ADD, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
			(byte) 0xFF };

	/**
	 * Main.
	 * 
	 * @param args
	 */
	public static void main(String[] args) {

		new NtagPwd();
	}

	/**
	 * Constructor.
	 */
	public NtagPwd() {

		/**
		 * The password.
		 */
		String myPwd = "toto";

		try {
			CardTerminal terminal = CardTerminalUtils.getTerminalByName("ACS ACR122");
			terminal.waitForCardPresent(5000);
			Card card = terminal.connect("*");
			CardChannel cardChannel = card.getBasicChannel();

			boolean hasPwd = hasAuth(cardChannel);
			System.out.println("=> Has PWD = " + hasPwd);

			if (hasPwd) {

				boolean auth = auth(cardChannel, myPwd);
				System.out.println("=> Auth = " + auth);

				boolean unset = unsetPwd(cardChannel);
				System.out.println("=> Remove password = " + unset);

			} else {

				boolean setPwd = setPwd(cardChannel, myPwd);
				System.out.println("=> Password set = " + setPwd);
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Check if authentication is needed.
	 * 
	 * @param cardChannel
	 * @return
	 */
	public boolean hasAuth(CardChannel cardChannel) {
		try {
			ResponseAPDU response = cardChannel.transmit(createCommand(IS_AUTH_CM));
			byte[] dataSetConfig = {};
			if (response.getSW1() == 144 && response.getSW2() == 0) {
				dataSetConfig = response.getData();
				System.out.println("Has Auth response = " + byteToHex(dataSetConfig));
				// No PWD : D5 43 00 - 04 00 00 FF - (...)

				// With PWD : D5 43 00 - 04 00 00 00 - (...)

				// Length 19 : header (3 bytes) + 4 blocks of 4 bytes
				return dataSetConfig.length == 19 && dataSetConfig[6] == (byte) 0x00;

			} else {
				System.out.println("Sw1 = " + response.getSW1() + " - SW2 = " + response.getSW2());
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return false;
	}

	/**
	 * Authentication method. Shall be call before writing data, changing or
	 * unsetting password when there is already a password.
	 * 
	 * @param cardChannel
	 * @param pwd
	 * @return
	 */
	public boolean auth(CardChannel cardChannel, String pwd) {
		boolean success = false;
		try {

			byte[] oPwd = extractArray(hashPwd(pwd), 0, 4);

			byte[] authCmd = concatArrays(AUTH_CM, oPwd);
			ResponseAPDU response = cardChannel.transmit(createCommand(authCmd));
			if (response.getSW1() == 144 && response.getSW2() == 0) {
				byte[] data = response.getData();
				System.out.println("Auth response = " + byteToHex(data));
				// Should be D5 43 00 (...) or D5 43 02 (...)
				// If D5 43 01, then auth failed
				success = checkResponse(data);
			} else {
				System.out.println("Sw1 = " + response.getSW1() + " - SW2 = " + response.getSW2());
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return success;
	}

	/**
	 * Set password method.
	 * 
	 * @param cardChannel
	 * @param pwd
	 * @return
	 */
	public boolean setPwd(CardChannel cardChannel, String pwd) {

		boolean success = false;
		try {
			byte[] nPwd = extractArray(hashPwd(pwd), 0, 4);
			ResponseAPDU response = cardChannel.transmit(createCommand(SET_CONFIG_CMD));
			byte[] dataSetConfig = {};
			if (response.getSW1() == 144 && response.getSW2() == 0) {
				dataSetConfig = response.getData();
				System.out.println("Set Auth Config response = " + byteToHex(dataSetConfig));
				// Should be D5 43 00 or D5 43 02
			} else {
				System.out.println("Sw1 = " + response.getSW1() + " - SW2 = " + response.getSW2());
			}

			byte[] pwdSetCmd = concatArrays(SET_PWD_CMD, nPwd);
			response = cardChannel.transmit(createCommand(pwdSetCmd));
			byte[] dataSetPwd = {};
			if (response.getSW1() == 144 && response.getSW2() == 0) {
				dataSetPwd = response.getData();
				System.out.println("Set Auth Pwd response = " + byteToHex(dataSetPwd));
				// Should be D5 43 00 or D5 43 02
			} else {
				System.out.println("Sw1 = " + response.getSW1() + " - SW2 = " + response.getSW2());
			}
			success = checkResponse(dataSetConfig) && checkResponse(dataSetPwd);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return success;
	}

	/**
	 * Unset the password.
	 * 
	 * @param cardChannel
	 * @return
	 */
	public boolean unsetPwd(CardChannel cardChannel) {

		boolean success = false;
		try {
			ResponseAPDU response = cardChannel.transmit(createCommand(UNSET_CONFIG_CMD));
			byte[] dataUnsetConfig = {};
			if (response.getSW1() == 144 && response.getSW2() == 0) {
				dataUnsetConfig = response.getData();
				System.out.println("Unset Auth Config response = " + byteToHex(dataUnsetConfig));
				// Should be D5 43 00 or D5 43 02
			} else {
				System.out.println("Sw1 = " + response.getSW1() + " - SW2 = " + response.getSW2());
			}
			response = cardChannel.transmit(createCommand(UNSET_PWD_CMD));
			byte[] dataUnsetPwd = {};
			if (response.getSW1() == 144 && response.getSW2() == 0) {
				dataUnsetPwd = response.getData();
				System.out.println("Unset Auth Pwd response = " + byteToHex(dataUnsetPwd));
				// Should be D5 43 00 or D5 43 02
			} else {
				System.out.println("Sw1 = " + response.getSW1() + " - SW2 = " + response.getSW2());
			}
			success = checkResponse(dataUnsetConfig) && checkResponse(dataUnsetPwd);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return success;
	}

	/**
	 * Hash the password.
	 * 
	 * @param pwd
	 * @return
	 */
	private static byte[] hashPwd(String pwd) {
		try {
			MessageDigest digest = MessageDigest.getInstance("MD5");
			digest.update(pwd.getBytes());
			return digest.digest();
		} catch (NoSuchAlgorithmException e) {

			return null;
		}

	}

	public static CommandAPDU createCommand(byte[] cmd) {
		byte[] fullcmd = concatArrays(
				new byte[] { (byte) 0xFF, 0, 0, 0, (byte) (cmd.length + 2), (byte) 0xD4, (byte) 0x42 }, cmd);
		return new CommandAPDU(fullcmd);
	}

	public static byte[] concatArrays(byte[] array1, byte[] array2) {

		byte[] tmp = new byte[array1.length + array2.length];
		System.arraycopy(array1, 0, tmp, 0, array1.length);
		System.arraycopy(array2, 0, tmp, array1.length, array2.length);
		return tmp;
	}

	public static byte[] extractArray(byte[] array, int start, int count) {
		byte[] tmp = new byte[count];
		System.arraycopy(array, start, tmp, 0, count);
		return tmp;
	}

	private static boolean checkResponse(byte[] data) {
		return (data.length >= 3) && data[0] == (byte) 0xD5 && data[1] == (byte) 0x43
				&& (data[2] == 0x00 || data[2] == 0x02);
	}

	public final static String byteToHex(byte[] data) {

		if (data.length > 0) {
			StringBuilder mess = new StringBuilder();
			for (int i = 0; i < data.length - 1; i++) {
				byte b = data[i];
				mess.append(String.format("%02X ", b));
			}
			mess.append(String.format("%02X", data[data.length - 1]));
			return mess.toString();
		} else {
			return "";
		}
	}
}
