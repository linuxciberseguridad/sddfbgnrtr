using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Xml;
using System.Xml.Serialization;
using BWP.Enterprise.Agent.Logging;

namespace BWP.Enterprise.Agent.Utils
{
    /// <summary>
    /// Helper de serialización para BWP Enterprise
    /// Maneja serialización a JSON, XML y formatos binarios
    /// </summary>
    public sealed class SerializationHelper
    {
        private static readonly Lazy<SerializationHelper> _instance = 
            new Lazy<SerializationHelper>(() => new SerializationHelper());
        
        public static SerializationHelper Instance => _instance.Value;
        
        private readonly LogManager _logManager;
        private readonly JsonSerializerOptions _jsonOptions;
        private readonly JsonSerializerOptions _jsonPrettyOptions;
        private readonly Dictionary<Type, XmlSerializer> _xmlSerializers;
        
        private SerializationHelper()
        {
            _logManager = LogManager.Instance;
            _xmlSerializers = new Dictionary<Type, XmlSerializer>();
            
            // Configurar opciones JSON
            _jsonOptions = new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                DictionaryKeyPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
                Converters = { 
                    new System.Text.Json.Serialization.JsonStringEnumConverter(JsonNamingPolicy.CamelCase),
                    new DateTimeConverter()
                }
            };
            
            _jsonPrettyOptions = new JsonSerializerOptions(_jsonOptions)
            {
                WriteIndented = true
            };
        }
        
        #region Serialización JSON
        
        /// <summary>
        /// Serializa objeto a JSON
        /// </summary>
        public string ToJson<T>(T obj, bool prettyPrint = false)
        {
            try
            {
                var options = prettyPrint ? _jsonPrettyOptions : _jsonOptions;
                return JsonSerializer.Serialize(obj, options);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error serializando a JSON: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error serializando a JSON: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Serializa objeto a JSON de forma asíncrona
        /// </summary>
        public async Task<string> ToJsonAsync<T>(T obj, bool prettyPrint = false)
        {
            try
            {
                var options = prettyPrint ? _jsonPrettyOptions : _jsonOptions;
                using (var stream = new MemoryStream())
                {
                    await JsonSerializer.SerializeAsync(stream, obj, options);
                    stream.Position = 0;
                    using (var reader = new StreamReader(stream))
                    {
                        return await reader.ReadToEndAsync();
                    }
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error serializando a JSON asíncrono: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error serializando a JSON: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Deserializa JSON a objeto
        /// </summary>
        public T FromJson<T>(string json)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(json))
                    return default;
                
                return JsonSerializer.Deserialize<T>(json, _jsonOptions);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error deserializando JSON: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error deserializando JSON: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Deserializa JSON a objeto de forma asíncrona
        /// </summary>
        public async Task<T> FromJsonAsync<T>(string json)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(json))
                    return default;
                
                var bytes = Encoding.UTF8.GetBytes(json);
                using (var stream = new MemoryStream(bytes))
                {
                    return await JsonSerializer.DeserializeAsync<T>(stream, _jsonOptions);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error deserializando JSON asíncrono: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error deserializando JSON: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Deserializa JSON con tipo dinámico
        /// </summary>
        public object FromJson(string json, Type type)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(json))
                    return null;
                
                return JsonSerializer.Deserialize(json, type, _jsonOptions);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error deserializando JSON dinámico: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error deserializando JSON: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Valida si un JSON es válido
        /// </summary>
        public bool IsValidJson(string json)
        {
            if (string.IsNullOrWhiteSpace(json))
                return false;
            
            try
            {
                JsonDocument.Parse(json);
                return true;
            }
            catch
            {
                return false;
            }
        }
        
        /// <summary>
        /// Minifica JSON
        /// </summary>
        public string MinifyJson(string json)
        {
            try
            {
                using (var doc = JsonDocument.Parse(json))
                using (var stream = new MemoryStream())
                {
                    var writer = new Utf8JsonWriter(stream, new JsonWriterOptions 
                    { 
                        Indented = false,
                        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                    });
                    
                    doc.WriteTo(writer);
                    writer.Flush();
                    
                    return Encoding.UTF8.GetString(stream.ToArray());
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error minificando JSON: {ex}", nameof(SerializationHelper));
                return json;
            }
        }
        
        /// <summary>
        /// Formatea JSON para legibilidad
        /// </summary>
        public string FormatJson(string json)
        {
            try
            {
                using (var doc = JsonDocument.Parse(json))
                using (var stream = new MemoryStream())
                {
                    var writer = new Utf8JsonWriter(stream, new JsonWriterOptions 
                    { 
                        Indented = true,
                        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
                    });
                    
                    doc.WriteTo(writer);
                    writer.Flush();
                    
                    return Encoding.UTF8.GetString(stream.ToArray());
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error formateando JSON: {ex}", nameof(SerializationHelper));
                return json;
            }
        }
        
        /// <summary>
        /// Serializa a JSON y guarda en archivo
        /// </summary>
        public async Task SaveJsonToFileAsync<T>(T obj, string filePath, bool prettyPrint = true)
        {
            try
            {
                var json = ToJson(obj, prettyPrint);
                await File.WriteAllTextAsync(filePath, json, Encoding.UTF8);
                
                _logManager.LogDebug($"JSON guardado en: {filePath}", nameof(SerializationHelper));
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error guardando JSON en archivo {filePath}: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error guardando JSON: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Carga y deserializa JSON desde archivo
        /// </summary>
        public async Task<T> LoadJsonFromFileAsync<T>(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    throw new FileNotFoundException($"Archivo no encontrado: {filePath}");
                }
                
                var json = await File.ReadAllTextAsync(filePath, Encoding.UTF8);
                return FromJson<T>(json);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cargando JSON desde archivo {filePath}: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error cargando JSON: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Serializa a JSON con compresión
        /// </summary>
        public async Task<byte[]> ToJsonCompressedAsync<T>(T obj)
        {
            try
            {
                var json = ToJson(obj, false);
                var bytes = Encoding.UTF8.GetBytes(json);
                
                using (var output = new MemoryStream())
                {
                    using (var gzip = new System.IO.Compression.GZipStream(output, 
                           System.IO.Compression.CompressionLevel.Optimal))
                    {
                        await gzip.WriteAsync(bytes, 0, bytes.Length);
                    }
                    
                    return output.ToArray();
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error serializando JSON comprimido: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error serializando JSON comprimido: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Deserializa JSON comprimido
        /// </summary>
        public async Task<T> FromJsonCompressedAsync<T>(byte[] compressedData)
        {
            try
            {
                using (var input = new MemoryStream(compressedData))
                using (var gzip = new System.IO.Compression.GZipStream(input, 
                       System.IO.Compression.CompressionMode.Decompress))
                using (var output = new MemoryStream())
                {
                    await gzip.CopyToAsync(output);
                    var json = Encoding.UTF8.GetString(output.ToArray());
                    return FromJson<T>(json);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error deserializando JSON comprimido: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error deserializando JSON comprimido: {ex.Message}", ex);
            }
        }
        
        #endregion
        
        #region Serialización XML
        
        /// <summary>
        /// Serializa objeto a XML
        /// </summary>
        public string ToXml<T>(T obj)
        {
            try
            {
                var serializer = GetXmlSerializer(typeof(T));
                using (var writer = new StringWriter())
                {
                    serializer.Serialize(writer, obj);
                    return writer.ToString();
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error serializando a XML: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error serializando a XML: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Serializa objeto a XML con formato
        /// </summary>
        public string ToXmlFormatted<T>(T obj)
        {
            try
            {
                var serializer = GetXmlSerializer(typeof(T));
                var settings = new XmlWriterSettings
                {
                    Indent = true,
                    IndentChars = "  ",
                    NewLineChars = "\n",
                    Encoding = Encoding.UTF8
                };
                
                using (var writer = new StringWriter())
                using (var xmlWriter = XmlWriter.Create(writer, settings))
                {
                    serializer.Serialize(xmlWriter, obj);
                    return writer.ToString();
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error serializando a XML formateado: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error serializando a XML: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Deserializa XML a objeto
        /// </summary>
        public T FromXml<T>(string xml)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(xml))
                    return default;
                
                var serializer = GetXmlSerializer(typeof(T));
                using (var reader = new StringReader(xml))
                {
                    return (T)serializer.Deserialize(reader);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error deserializando XML: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error deserializando XML: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Deserializa XML desde archivo
        /// </summary>
        public async Task<T> FromXmlFileAsync<T>(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    throw new FileNotFoundException($"Archivo no encontrado: {filePath}");
                }
                
                var xml = await File.ReadAllTextAsync(filePath, Encoding.UTF8);
                return FromXml<T>(xml);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cargando XML desde archivo {filePath}: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error cargando XML: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Guarda objeto como XML en archivo
        /// </summary>
        public async Task SaveXmlToFileAsync<T>(T obj, string filePath, bool formatted = true)
        {
            try
            {
                var xml = formatted ? ToXmlFormatted(obj) : ToXml(obj);
                await File.WriteAllTextAsync(filePath, xml, Encoding.UTF8);
                
                _logManager.LogDebug($"XML guardado en: {filePath}", nameof(SerializationHelper));
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error guardando XML en archivo {filePath}: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error guardando XML: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Valida XML contra esquema
        /// </summary>
        public bool ValidateXml(string xml, string schemaPath)
        {
            try
            {
                var settings = new XmlReaderSettings
                {
                    ValidationType = ValidationType.Schema
                };
                
                settings.Schemas.Add(null, schemaPath);
                
                using (var reader = new StringReader(xml))
                using (var xmlReader = XmlReader.Create(reader, settings))
                {
                    while (xmlReader.Read()) { }
                    return true;
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error validando XML: {ex}", nameof(SerializationHelper));
                return false;
            }
        }
        
        /// <summary>
        /// Transforma XML usando XSLT
        /// </summary>
        public string TransformXml(string xml, string xsltPath)
        {
            try
            {
                var xslt = new System.Xml.Xsl.XslCompiledTransform();
                xslt.Load(xsltPath);
                
                using (var xmlReader = XmlReader.Create(new StringReader(xml)))
                using (var writer = new StringWriter())
                {
                    xslt.Transform(xmlReader, null, writer);
                    return writer.ToString();
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error transformando XML: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error transformando XML: {ex.Message}", ex);
            }
        }
        
        #endregion
        
        #region Serialización Binaria
        
        /// <summary>
        /// Serializa objeto a binario
        /// </summary>
        public byte[] ToBinary<T>(T obj)
        {
            try
            {
                using (var stream = new MemoryStream())
                {
                    var formatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                    formatter.Serialize(stream, obj);
                    return stream.ToArray();
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error serializando a binario: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error serializando a binario: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Deserializa binario a objeto
        /// </summary>
        public T FromBinary<T>(byte[] data)
        {
            try
            {
                using (var stream = new MemoryStream(data))
                {
                    var formatter = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();
                    return (T)formatter.Deserialize(stream);
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error deserializando binario: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error deserializando binario: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Guarda objeto como binario en archivo
        /// </summary>
        public async Task SaveBinaryToFileAsync<T>(T obj, string filePath)
        {
            try
            {
                var data = ToBinary(obj);
                await File.WriteAllBytesAsync(filePath, data);
                
                _logManager.LogDebug($"Binario guardado en: {filePath}", nameof(SerializationHelper));
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error guardando binario en archivo {filePath}: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error guardando binario: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Carga y deserializa binario desde archivo
        /// </summary>
        public async Task<T> LoadBinaryFromFileAsync<T>(string filePath)
        {
            try
            {
                if (!File.Exists(filePath))
                {
                    throw new FileNotFoundException($"Archivo no encontrado: {filePath}");
                }
                
                var data = await File.ReadAllBytesAsync(filePath);
                return FromBinary<T>(data);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error cargando binario desde archivo {filePath}: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error cargando binario: {ex.Message}", ex);
            }
        }
        
        #endregion
        
        #region Conversión entre Formatos
        
        /// <summary>
        /// Convierte XML a JSON
        /// </summary>
        public string XmlToJson(string xml, bool prettyPrint = false)
        {
            try
            {
                var doc = new XmlDocument();
                doc.LoadXml(xml);
                
                var json = JsonSerializer.Serialize(doc, _jsonOptions);
                return prettyPrint ? FormatJson(json) : MinifyJson(json);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error convirtiendo XML a JSON: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error convirtiendo XML a JSON: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Convierte JSON a XML
        /// </summary>
        public string JsonToXml(string json, string rootElement = "root")
        {
            try
            {
                using (var doc = JsonDocument.Parse(json))
                {
                    var xmlDoc = new XmlDocument();
                    var root = xmlDoc.CreateElement(rootElement);
                    xmlDoc.AppendChild(root);
                    
                    ConvertJsonToXml(doc.RootElement, root, xmlDoc);
                    
                    using (var writer = new StringWriter())
                    {
                        xmlDoc.Save(writer);
                        return writer.ToString();
                    }
                }
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error convirtiendo JSON a XML: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error convirtiendo JSON a XML: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Convierte binario a JSON
        /// </summary>
        public string BinaryToJson<T>(byte[] binaryData)
        {
            try
            {
                var obj = FromBinary<T>(binaryData);
                return ToJson(obj, true);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error convirtiendo binario a JSON: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error convirtiendo binario a JSON: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Convierte JSON a binario
        /// </summary>
        public byte[] JsonToBinary<T>(string json)
        {
            try
            {
                var obj = FromJson<T>(json);
                return ToBinary(obj);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error convirtiendo JSON a binario: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error convirtiendo JSON a binario: {ex.Message}", ex);
            }
        }
        
        #endregion
        
        #region Métodos de Utilidad
        
        /// <summary>
        /// Clona objeto usando serialización
        /// </summary>
        public T DeepClone<T>(T obj)
        {
            try
            {
                var json = ToJson(obj);
                return FromJson<T>(json);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error clonando objeto: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error clonando objeto: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Compara objetos por serialización
        /// </summary>
        public bool AreEqual<T>(T obj1, T obj2)
        {
            try
            {
                var json1 = ToJson(obj1);
                var json2 = ToJson(obj2);
                return json1 == json2;
            }
            catch
            {
                return false;
            }
        }
        
        /// <summary>
        /// Obtiene diferencias entre objetos
        /// </summary>
        public Dictionary<string, object> GetDifferences<T>(T obj1, T obj2)
        {
            try
            {
                var dict1 = FromJson<Dictionary<string, object>>(ToJson(obj1));
                var dict2 = FromJson<Dictionary<string, object>>(ToJson(obj2));
                
                var differences = new Dictionary<string, object>();
                
                foreach (var key in dict1.Keys.Union(dict2.Keys))
                {
                    var has1 = dict1.TryGetValue(key, out var val1);
                    var has2 = dict2.TryGetValue(key, out var val2);
                    
                    if (!has1 || !has2 || !Equals(val1, val2))
                    {
                        differences[key] = new 
                        {
                            Object1 = val1,
                            Object2 = val2,
                            HasValue1 = has1,
                            HasValue2 = has2
                        };
                    }
                }
                
                return differences;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error obteniendo diferencias: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error obteniendo diferencias: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Serializa excepción para logging
        /// </summary>
        public string SerializeException(Exception ex, bool includeStackTrace = true)
        {
            try
            {
                var errorInfo = new
                {
                    Type = ex.GetType().Name,
                    Message = ex.Message,
                    Source = ex.Source,
                    StackTrace = includeStackTrace ? ex.StackTrace : null,
                    InnerException = ex.InnerException != null ? SerializeException(ex.InnerException, includeStackTrace) : null,
                    Data = ex.Data.Count > 0 ? ex.Data : null,
                    Timestamp = DateTime.UtcNow
                };
                
                return ToJson(errorInfo, true);
            }
            catch
            {
                return $"Error serializando excepción: {ex.Message}";
            }
        }
        
        /// <summary>
        /// Serializa diccionario de propiedades
        /// </summary>
        public string SerializeProperties(Dictionary<string, object> properties)
        {
            try
            {
                return ToJson(properties, true);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error serializando propiedades: {ex}", nameof(SerializationHelper));
                return $"{{ \"error\": \"Error serializando propiedades: {ex.Message}\" }}";
            }
        }
        
        /// <summary>
        /// Serializa con tipo incluido
        /// </summary>
        public string SerializeWithType<T>(T obj)
        {
            try
            {
                var wrapper = new
                {
                    Type = typeof(T).FullName,
                    Assembly = typeof(T).Assembly.GetName().Name,
                    Timestamp = DateTime.UtcNow,
                    Data = obj
                };
                
                return ToJson(wrapper, true);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error serializando con tipo: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error serializando con tipo: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Deserializa con tipo incluido
        /// </summary>
        public object DeserializeWithType(string json)
        {
            try
            {
                var wrapper = FromJson<TypeWrapper>(json);
                
                var type = Type.GetType($"{wrapper.Type}, {wrapper.Assembly}");
                if (type == null)
                {
                    throw new TypeLoadException($"No se pudo cargar el tipo: {wrapper.Type}");
                }
                
                var dataJson = ToJson(wrapper.Data);
                return FromJson(dataJson, type);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error deserializando con tipo: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error deserializando con tipo: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Serializa para transmisión por red
        /// </summary>
        public async Task<byte[]> SerializeForTransmissionAsync<T>(T obj, CompressionType compression = CompressionType.None)
        {
            try
            {
                byte[] data;
                
                switch (compression)
                {
                    case CompressionType.None:
                        var json = ToJson(obj, false);
                        data = Encoding.UTF8.GetBytes(json);
                        break;
                        
                    case CompressionType.GZip:
                        data = await ToJsonCompressedAsync(obj);
                        break;
                        
                    case CompressionType.Deflate:
                        var json2 = ToJson(obj, false);
                        var bytes = Encoding.UTF8.GetBytes(json2);
                        
                        using (var output = new MemoryStream())
                        {
                            using (var deflate = new System.IO.Compression.DeflateStream(output, 
                                   System.IO.Compression.CompressionLevel.Optimal))
                            {
                                await deflate.WriteAsync(bytes, 0, bytes.Length);
                            }
                            data = output.ToArray();
                        }
                        break;
                        
                    default:
                        throw new ArgumentException($"Tipo de compresión no soportado: {compression}");
                }
                
                // Agregar header con metadatos
                var header = new TransmissionHeader
                {
                    Compression = compression,
                    OriginalSize = data.Length,
                    Timestamp = DateTime.UtcNow,
                    Checksum = ComputeChecksum(data)
                };
                
                var headerJson = ToJson(header, false);
                var headerBytes = Encoding.UTF8.GetBytes(headerJson);
                var headerLength = BitConverter.GetBytes(headerBytes.Length);
                
                // Construir paquete completo
                var packet = new byte[4 + headerBytes.Length + data.Length];
                Buffer.BlockCopy(headerLength, 0, packet, 0, 4);
                Buffer.BlockCopy(headerBytes, 0, packet, 4, headerBytes.Length);
                Buffer.BlockCopy(data, 0, packet, 4 + headerBytes.Length, data.Length);
                
                return packet;
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error serializando para transmisión: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error serializando para transmisión: {ex.Message}", ex);
            }
        }
        
        /// <summary>
        /// Deserializa desde transmisión por red
        /// </summary>
        public async Task<T> DeserializeFromTransmissionAsync<T>(byte[] packet)
        {
            try
            {
                // Leer header
                var headerLength = BitConverter.ToInt32(packet, 0);
                var headerJson = Encoding.UTF8.GetString(packet, 4, headerLength);
                var header = FromJson<TransmissionHeader>(headerJson);
                
                // Leer datos
                var data = new byte[header.OriginalSize];
                Buffer.BlockCopy(packet, 4 + headerLength, data, 0, data.Length);
                
                // Verificar checksum
                var checksum = ComputeChecksum(data);
                if (checksum != header.Checksum)
                {
                    throw new SerializationException("Checksum no coincide - datos corruptos");
                }
                
                // Descomprimir si es necesario
                byte[] decompressedData;
                
                switch (header.Compression)
                {
                    case CompressionType.None:
                        decompressedData = data;
                        break;
                        
                    case CompressionType.GZip:
                        using (var input = new MemoryStream(data))
                        using (var gzip = new System.IO.Compression.GZipStream(input, 
                               System.IO.Compression.CompressionMode.Decompress))
                        using (var output = new MemoryStream())
                        {
                            await gzip.CopyToAsync(output);
                            decompressedData = output.ToArray();
                        }
                        break;
                        
                    case CompressionType.Deflate:
                        using (var input = new MemoryStream(data))
                        using (var deflate = new System.IO.Compression.DeflateStream(input, 
                               System.IO.Compression.CompressionMode.Decompress))
                        using (var output = new MemoryStream())
                        {
                            await deflate.CopyToAsync(output);
                            decompressedData = output.ToArray();
                        }
                        break;
                        
                    default:
                        throw new SerializationException($"Tipo de compresión no soportado: {header.Compression}");
                }
                
                // Deserializar
                var json = Encoding.UTF8.GetString(decompressedData);
                return FromJson<T>(json);
            }
            catch (Exception ex)
            {
                _logManager.LogError($"Error deserializando desde transmisión: {ex}", nameof(SerializationHelper));
                throw new SerializationException($"Error deserializando desde transmisión: {ex.Message}", ex);
            }
        }
        
        #endregion
        
        #region Métodos Privados
        
        /// <summary>
        /// Obtiene o crea XmlSerializer para tipo
        /// </summary>
        private XmlSerializer GetXmlSerializer(Type type)
        {
            lock (_xmlSerializers)
            {
                if (!_xmlSerializers.TryGetValue(type, out var serializer))
                {
                    serializer = new XmlSerializer(type);
                    _xmlSerializers[type] = serializer;
                }
                
                return serializer;
            }
        }
        
        /// <summary>
        /// Convierte JsonElement a Xml
        /// </summary>
        private void ConvertJsonToXml(JsonElement element, XmlElement parent, XmlDocument doc)
        {
            switch (element.ValueKind)
            {
                case JsonValueKind.Object:
                    foreach (var property in element.EnumerateObject())
                    {
                        var child = doc.CreateElement(property.Name);
                        parent.AppendChild(child);
                        ConvertJsonToXml(property.Value, child, doc);
                    }
                    break;
                    
                case JsonValueKind.Array:
                    foreach (var item in element.EnumerateArray())
                    {
                        var child = doc.CreateElement("item");
                        parent.AppendChild(child);
                        ConvertJsonToXml(item, child, doc);
                    }
                    break;
                    
                case JsonValueKind.String:
                    parent.InnerText = element.GetString();
                    break;
                    
                case JsonValueKind.Number:
                    parent.InnerText = element.GetRawText();
                    break;
                    
                case JsonValueKind.True:
                    parent.InnerText = "true";
                    break;
                    
                case JsonValueKind.False:
                    parent.InnerText = "false";
                    break;
                    
                case JsonValueKind.Null:
                    parent.InnerText = "null";
                    break;
            }
        }
        
        /// <summary>
        /// Calcula checksum de datos
        /// </summary>
        private string ComputeChecksum(byte[] data)
        {
            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(data);
                return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
            }
        }
        
        #endregion
        
        #region Clases Internas
        
        private class DateTimeConverter : System.Text.Json.Serialization.JsonConverter<DateTime>
        {
            public override DateTime Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
            {
                return DateTime.Parse(reader.GetString());
            }
            
            public override void Write(Utf8JsonWriter writer, DateTime value, JsonSerializerOptions options)
            {
                writer.WriteStringValue(value.ToString("o")); // ISO 8601
            }
        }
        
        private class TypeWrapper
        {
            public string Type { get; set; }
            public string Assembly { get; set; }
            public DateTime Timestamp { get; set; }
            public object Data { get; set; }
        }
        
        private class TransmissionHeader
        {
            public CompressionType Compression { get; set; }
            public int OriginalSize { get; set; }
            public DateTime Timestamp { get; set; }
            public string Checksum { get; set; }
        }
        
        #endregion
    }
    
    #region Clases y Enums Públicos
    
    public enum SerializationFormat
    {
        Json,
        Xml,
        Binary,
        JsonCompressed,
        XmlCompressed
    }
    
    public enum CompressionType
    {
        None,
        GZip,
        Deflate
    }
    
    public class SerializationException : Exception
    {
        public SerializationException(string message) : base(message) { }
        public SerializationException(string message, Exception innerException) : base(message, innerException) { }
    }
    
    public class SerializationOptions
    {
        public SerializationFormat Format { get; set; } = SerializationFormat.Json;
        public bool PrettyPrint { get; set; } = true;
        public CompressionType Compression { get; set; } = CompressionType.None;
        public bool IncludeTypeInfo { get; set; } = false;
        public Dictionary<string, object> CustomOptions { get; set; } = new Dictionary<string, object>();
    }
    
    public class SerializationResult
    {
        public bool Success { get; set; }
        public string Data { get; set; }
        public byte[] BinaryData { get; set; }
        public long Size { get; set; }
        public TimeSpan SerializationTime { get; set; }
        public string Error { get; set; }
        public SerializationOptions Options { get; set; }
    }
    
    #endregion
}