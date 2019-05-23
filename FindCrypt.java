// Finds Crypto constants in a binary
//@category Crypto

/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import java.io.BufferedInputStream;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.net.URLConnection;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.ReadableByteChannel;
import java.security.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.zip.GZIPInputStream;

import docking.widgets.dialogs.MultiLineMessageDialog;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.util.Msg;

public class FindCrypt extends GhidraScript {

	public static class DatabaseManager {
		// Structure of database file, for reference.
		/********************************************************
		 | MAGIC (4)    | Total Entries (2)          	        |
		 | NameSize (4) | Name (x) | isCompressed(1) | BSize(4) |
		 | Buffer (x)   | ...                                   |
		 ********************************************************/
		
		// Structure of the database entry.
		public class EntryInfo {
			private byte[] _buffer;
			private String _name;
			
			public EntryInfo(byte[] _buff, String _name) {
				this._buffer = _buff;
				this._name = _name;
			}
		}
		
		private boolean   		 	_loaded = false;
		private static final int 	_EXPECTED_MAGIC = 0xD3010401;
		private short     		 	_totalEntries 	 = 0;
	
		private String _dbPath;

		private ArrayList<EntryInfo> _consts = new ArrayList<>();

		
		public int DbSize() {
			return this._totalEntries;
		}

		public ArrayList<EntryInfo> getConsts() {
			return _consts;
		}
		
		public DatabaseManager(String path) {
			_dbPath = path;
		}

		public void loadDb() throws Exception {

			if (!this._loaded) {
				
					DataInputStream _stream = new DataInputStream(new FileInputStream(_dbPath));
					var _curMagic = _stream.readInt();
					
					if (_curMagic != _EXPECTED_MAGIC)
						throw new Exception("Specified database file has a different magic from the expected one.");
					
					this._totalEntries = _stream.readShort();
					if (this._totalEntries == 0) {
						throw new Exception("FindCrypt Error: Database had 0 entries");
					}
					
					for (var i = 0; i < this._totalEntries; i++) {
						var _nameSize = _stream.readInt();
						if (_nameSize == 0)
							throw new Exception("An entry has 0 length name.");
						var _name = new byte[_nameSize];
						_stream.read(_name);
						
						var _isCompressed = _stream.readByte();
						
						var _buffSize = _stream.readInt();
						if (_buffSize == 0) 
							throw new Exception("An entry has no buffer (" + _name + ")");
						var _buff = new byte[_buffSize];
						_stream.read(_buff);
						
						if (_isCompressed == 0x01) {
							// https://stackoverflow.com/questions/12531579/uncompress-a-gzip-string-in-java
							ByteArrayInputStream bytein = new ByteArrayInputStream(_buff);
							GZIPInputStream gzin = new GZIPInputStream(bytein);
							ByteArrayOutputStream byteout = new ByteArrayOutputStream();

							int res = 0;
							byte buf[] = new byte[1024];
							while (res >= 0) {
							    res = gzin.read(buf, 0, buf.length);
							    if (res > 0) {
							        byteout.write(buf, 0, res);
							    }
							}
							byte uncompressed[] = byteout.toByteArray();
							
							this._consts.add(new EntryInfo(uncompressed, new String(_name, "UTF-8")));
						} else 
							this._consts.add(new EntryInfo(_buff, new String(_name, "UTF-8")));
					}
					
					_stream.close();
					this._loaded = true;
					
				
			}
			
		}
	}

	@Override
	protected void run() throws Exception {
		
		println("FindCrypt - Ghidra Edition by d3vil401 (https://d3vsite.org)\n" +
		        "Original idea by Ilfak Guilfanov (http://hexblog.com)\n");
		
		if (isRunningHeadless()) {
			// Nothing to do I guess?
		}
		
		if (currentProgram == null) {
			println("No program loaded, aborting.");
			return;
		}
		
		String scriptDir = System.getProperty("user.home") + File.separator + "ghidra_scripts" + File.separator;
		DatabaseManager dbm = new DatabaseManager(scriptDir + "database.d3v");
		dbm.loadDb();

		println("Loaded " + dbm.DbSize() + " signatures.");
		
		var _ctr = 0;
		var _formatted = "";
		
		for (var alg: dbm.getConsts() ) {
			monitor.checkCanceled();
			
			var _found = currentProgram.getMemory().findBytes(currentProgram.getMinAddress(), alg._buffer, null, true, monitor);
			if (_found != null) {
				println("Found " + alg._name + ": 0x" + String.format("%08X", _found.getOffset()));
				// I added a counter, in case we have duplicate patterns.
				
				_formatted += String.format("%s -> 0x%08X\n", alg._name, _found.getOffset());
				_ctr++;
			}
		}
		
		// Only show results if something has been found.
		if (_ctr > 1)
		{
			println("A total of " + _ctr + " signatures have been found.");
		}
		
		_formatted = "";
	}

}
