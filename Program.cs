using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PGRDecrypt
{
	class Program
	{
		static void OutputUsage(string title)
		{
			Console.Write(
$@"{title}

Windows Explorer Drag-n-Drop Usage:
  Simply drop an encrypted PGR file into {AppDomain.CurrentDomain.FriendlyName} to create a new decrypted PGR file.

Command Line Usage:
  {AppDomain.CurrentDomain.FriendlyName} [-s] <source> [-d <destination>] [-k <decryptionkey> [-b64]] [-o]

  -s source               Path of encrypted PGR file to load.
  -d destination          Path of decrypted PGR file to save.
                            Default = {{source}}.decrypted
  -k keyfile              Key file to decrypt with.
                             Default = {AppDomain.CurrentDomain.BaseDirectory}{defaultKeyFilename}

Press any key to exit . . ."
			);

			Console.ReadKey();
		}

		const string defaultKeyFilename = "keyfile.txt";

		struct Block
		{
			public uint UncompressedSize;
			public uint CompressedSize;
			public ushort Flags;
		}

		struct DirectoryInfo
		{
			public ulong Offset;
			public ulong Size;
			public uint Flags;
			public string Path;
		}

		static void Main(string[] args)
		{
			if (args.Length == 0)
			{
				OutputUsage("Tool to decrypt PGR files by Lamp");
				return;
			}
			string sArg = null;
			string dArg = null;
			string kArg = null;
			for (int i = 0, nexti = 1; i < args.Length; i = nexti, nexti++)
			{
				var arg = args[i];
				if (arg.Equals("-s") && args.Length > nexti)
				{
					sArg = args[nexti++];
				}
				else if (arg.Equals("-d") && args.Length > nexti)
				{
					dArg = args[nexti++];
				}
				else if (arg.Equals("-k") && args.Length > nexti)
				{
					kArg = args[nexti++];
				}
				else
				{
					if (!string.IsNullOrEmpty(sArg))
					{
						OutputUsage("Multiple source files are not supported!");
						return;
					}
					sArg = args[i];
				}
			}

			if (string.IsNullOrEmpty(sArg))
			{
				OutputUsage("Source path not specified!");
				return;
			}

			if (!File.Exists(sArg))
			{
				OutputUsage($"Source file '{Path.GetFullPath(sArg)}' does not exist!");
				return;
			}

			if (string.IsNullOrEmpty(dArg))
			{
				dArg = Path.GetFullPath(sArg) + ".decrypted";
			}

			if (File.Exists(dArg) || Directory.Exists(dArg))
			{
				OutputUsage($"Destination '{Path.GetFullPath(dArg)}' already exist!");
				return;
			}

			string[] keys;
			string keyfile;
			if (string.IsNullOrEmpty(kArg))
			{
				keyfile = AppDomain.CurrentDomain.BaseDirectory + defaultKeyFilename;
				if (!File.Exists(keyfile))
				{
					File.WriteAllText(keyfile, "kurokurokurokuro\r\ny5XPvqLOrCokWRIa");
					/*OutputUsage($"{keyfile} not found! Please use -k switch!");
					return;*/
				}
			}
			else
			{
				keyfile = kArg;
				if (!File.Exists(keyfile))
				{
					OutputUsage($"{keyfile} not found!");
					return;
				}
			}
			try
			{
				keys = File.ReadAllLines(keyfile);
			}
			catch (Exception e)
			{
				Console.WriteLine(
$@"An error occurred trying to read {keyfile}:

{e.Message}

{e.StackTrace}"
);
				Console.ReadKey();
				return;
			}

#if !DEBUG
			try
#endif
			{
				using (Stream file = File.OpenRead(sArg))
				{
					using (FileReader reader = new FileReader(file, EndianType.BigEndian))
					{
						if (!reader.TryReadStringNullTerm(out string type) || type != "UnityFS") // Type
						{
							throw new NotSupportedException("File is not UnityFS");
						}
						if (!reader.TryReadInt32(out int version) ||                                   // Version
							!reader.TryReadStringNullTerm(out string _) ||                       // UnityWebBundleVersion
							!reader.TryReadStringNullTerm(out string _))                         // UnityWebMinimumRevision
						{
							throw new InvalidDataException("Cannot read file header");
						}
						long bundleSizePtr = file.Position;
						if (!reader.TryReadUInt64(out ulong bundleSize) ||                       // BundleSize **** Need to update too after stripping PGR header (-= 0x46)
							!reader.TryReadInt32(out int metadataSize) ||                        // MetadataSize
							metadataSize == 0 ||
							!reader.TryReadInt32(out int uncompressedMetadataSize) ||            // UncompressedMetadataSize
							uncompressedMetadataSize < 24 ||
							!reader.TryReadInt32(out int flags))                                 // Flags **** Need to update too after stripping PGR header (&= 0xFFFFFDFF)
						{
							throw new InvalidDataException("Cannot read file header");
						}
						if ((flags & 0x200) == 0)
						{
							throw new NotSupportedException("File is not encrypted");
						}
						bool goodkey = false;
						PGR pgr = null;                                                 // **** Need to strip PGR header
						foreach (string key in keys)
						{
							PGR.UpdateKey(key);
							try
							{
								pgr = new PGR(reader);
								goodkey = true;
								break;
							}
							catch (Exception ex)
							{
								if (ex.Message == "Invalid Signature !!")
								{
									reader.Stream.Seek(-0x46, SeekOrigin.Current);
								}
							}
						}
						if (!goodkey)
						{
							throw new Exception("Key file provided is invalid");
						}
						Console.WriteLine("Reading metadata...");
						if ((flags & 0x00000080) != 0)
						{
							long metaposition = (long)bundleSize - metadataSize;
							if (metaposition < 0 || metaposition > file.Length)
							{
								throw new DataMisalignedException("Metadata offset is out of bounds");
							}
							throw new NotImplementedException($"Unsupported metadata position");
							file.Position = metaposition;
						}
						if ((flags & 0x0000003e) != 2)
						{
							throw new NotImplementedException($"Compresstion type '0x{flags & 0x0000003f:X2}' is not supported");
						}

						long padding = 0;
						if (version >= 7)
						{
							padding -= file.Position;
							file.Position = (long)Math.Ceiling((decimal)file.Position / 16) * 16;
							padding += file.Position;
						}

						List<Block> blocks = new List<Block>();
						List<DirectoryInfo> directories = new List<DirectoryInfo>();

						using (MemoryStream uncompressedMetadata = new MemoryStream(new byte[uncompressedMetadataSize]))
						{
							using (Lz4DecodeStream decodeStream = new Lz4DecodeStream(file, metadataSize))
							{
								decodeStream.ReadBuffer(uncompressedMetadata, uncompressedMetadataSize);
								uncompressedMetadata.Position = 0;
								using (FileReader metaReader = new FileReader(uncompressedMetadata, EndianType.BigEndian))
								{
									if (!metaReader.TryReadHash128(out Guid _))
									{
										throw new InvalidDataException("Cannot read file metadata");
									}

									if (!metaReader.TryReadUInt32(out uint blockcount) || blockcount * 10 + 20 > uncompressedMetadataSize)
									{
										throw new InsufficientMemoryException($"Block count of {blockcount} is too large for metadata size");
									}
									string plural = (blockcount == 1) ? "" : "s";
									Console.WriteLine($"{blockcount} block{plural} found:");
									for (int i = 0; i < blockcount; i++)
									{
										metaReader.TryReadUInt32(out uint uncompressedsize);
										metaReader.TryReadUInt32(out uint compressedsize);
										metaReader.TryReadUInt16(out ushort blockflags);
										Console.WriteLine($"  {i}: ({uncompressedsize}) {compressedsize} 0x{blockflags:X4}");
										blocks.Add(new Block { UncompressedSize = uncompressedsize, CompressedSize = compressedsize, Flags = blockflags });
									}

									if (!metaReader.TryReadUInt32(out uint directorycount) || directorycount * 10 + blockcount * 10 + 20 > uncompressedMetadataSize)
									{
										throw new InsufficientMemoryException($"Directory count of {directorycount} is too large for metadata size");
									}
									plural = (directorycount == 1) ? "y" : "ies";
									Console.WriteLine($"{directorycount} director{plural} found:");
									for (int i = 0; i < directorycount; i++)
									{
										metaReader.TryReadUInt64(out ulong offset);
										metaReader.TryReadUInt64(out ulong size);
										metaReader.TryReadUInt32(out uint directoryflags);
#warning TODO: Limit string parsing to remaining array size
										metaReader.TryReadStringNullTerm(out string path);
										Console.WriteLine($"  {i}: @{offset:X} {size} {directoryflags} \"{path}\"");
										directories.Add(new DirectoryInfo { Offset = offset, Size = size, Flags = directoryflags, Path = path });
									}
								}
							}
						}

						if (version >= 7)
						{
							padding -= file.Position;
							file.Position = (long)Math.Ceiling((decimal)file.Position / 16) * 16;
							padding += file.Position;
						}

						using (FileStream writer = File.OpenWrite(dArg))
						{
							long blockPtr = file.Position;
							file.Position = 0;

							// Write header
							for (int i = 0; i < (int)blockPtr - metadataSize - 0x46 - padding; i++)
							{
								writer.WriteByte(reader.ReadByte());
							}

							// Patch out encyption flag
							// (even though it is ignored by most 3rd party tools)
							writer.Position -= 2;
							writer.WriteByte((byte)(flags >> 8 & 0xFD));
							writer.WriteByte((byte)(flags));

							// Skip encryption header
							file.Position = blockPtr - metadataSize - padding;

							if (version >= 7)
							{
								file.Position = (long)Math.Ceiling((decimal)file.Position / 16) * 16;
								long newpadding = (long)Math.Ceiling((decimal)writer.Position / 16) * 16;
								while (writer.Position < newpadding)
								{
									writer.WriteByte(0x00);
								}
							}

							// Write metadata
							for (int i = 0; i < metadataSize; i++)
							{
								writer.WriteByte(reader.ReadByte());
#warning TODO: Patch out encrypted block flag in metadata
							}

							if (version >= 7)
							{
								file.Position = (long)Math.Ceiling((decimal)file.Position / 16) * 16;
								long newpadding = (long)Math.Ceiling((decimal)writer.Position / 16) * 16;
								while (writer.Position < newpadding)
								{
									writer.WriteByte(0x00);
								}
							}

							for (int i = 0; i < blocks.Count; i++)
							{
								Block block = blocks[i];
								if ((block.Flags & 0x0000003e) != 2 && (block.Flags & 0x0000003f) != 0)
								{
									throw new NotImplementedException($"Compresstion type '0x{block.Flags & 0x0000003f:X2}' is not supported");
								}
								int compressedSize = (int)block.CompressedSize;
								byte[] compressedBytes = new byte[compressedSize];
								reader.Read(compressedBytes, 0, compressedSize);
								if ((block.Flags & 0x100) != 0 && (block.Flags & 0x0000003f) != 0)
								{
									pgr.DecryptBlock(compressedBytes, compressedSize, i);
								}

								Console.WriteLine($"Decrypted block {i} of {blocks.Count}");
								writer.Write(compressedBytes, 0, compressedSize);
							}

							// Patch bundles size
							writer.Position = bundleSizePtr;
							writer.WriteByte((byte)(writer.Length >> 56));
							writer.WriteByte((byte)(writer.Length >> 48));
							writer.WriteByte((byte)(writer.Length >> 40));
							writer.WriteByte((byte)(writer.Length >> 32));
							writer.WriteByte((byte)(writer.Length >> 24));
							writer.WriteByte((byte)(writer.Length >> 16));
							writer.WriteByte((byte)(writer.Length >> 8));
							writer.WriteByte((byte)(writer.Length));
						}
					}
				}
			}
#if !DEBUG
			catch (Exception e)
			{
				Console.WriteLine(
$@"An error occurred trying to read {sArg}
{e.StackTrace}

{e.Message}"
);
				Console.ReadKey();
				return;
			}
#endif
		}
	}
}
