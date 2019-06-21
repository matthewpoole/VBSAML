Imports Microsoft.VisualBasic
Imports System
Imports System.Web
Imports System.IO
Imports System.Xml
Imports System.Security.Cryptography.X509Certificates
'Imports System.Security.Cryptography.Xml
Imports System.IO.Compression
Imports System.Text
Imports System.Security.Cryptography

Namespace samlConsume


    '  to prevent upgrading to .net45 we create a SHA256 Signing
    Public NotInheritable Class RSAPKCS1SHA256SignatureDescription : Inherits SignatureDescription

        Public Sub New()
            KeyAlgorithm = GetType(RSACryptoServiceProvider).FullName
            DigestAlgorithm = GetType(SHA256Managed).FullName
            FormatterAlgorithm = GetType(RSAPKCS1SignatureFormatter).FullName
            DeformatterAlgorithm = GetType(RSAPKCS1SignatureDeformatter).FullName
        End Sub

        Public Overrides Function CreateDeformatter(key As AsymmetricAlgorithm) As AsymmetricSignatureDeformatter
            If key Is Nothing Then
                Throw New Exception()
            End If

            Dim deformatter As RSAPKCS1SignatureDeformatter = New RSAPKCS1SignatureDeformatter(key)
            deformatter.SetHashAlgorithm("SHA256")
            Return deformatter
        End Function

        Public Overrides Function CreateFormatter(key As AsymmetricAlgorithm) As AsymmetricSignatureFormatter
            If key Is Nothing Then
                Throw New Exception()
            End If

            Dim formatter As RSAPKCS1SignatureFormatter = New RSAPKCS1SignatureFormatter(key)
            formatter.SetHashAlgorithm("SHA256")
            Return formatter
        End Function

        Private Shared _initialized As Boolean = False

        Public Shared Sub Init()
            If Not _initialized Then
                CryptoConfig.AddAlgorithm(GetType(RSAPKCS1SHA256SignatureDescription), "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
            End If
        End Sub

    End Class

    Public Class Certificate
        Public cert As X509Certificate2

        Public Sub LoadCertificate(certificate As String)
            LoadCertificate(StringToByteArray(certificate))
        End Sub
        Public Sub LoadCertificate(certificate As Byte())
            cert = New X509Certificate2(certificate)
        End Sub

        Private Function StringToByteArray(st As String) As Byte()
            Dim bytes(st.Length) As Byte

            For i As Integer = 0 To st.Length - 1
                bytes(i) = Convert.ToByte(st(i))
            Next
            Return bytes
        End Function

    End Class

    Public Class Response
        Private _xmlDoc As XmlDocument
        Private _certificate As Certificate
        Private _xmlNameSpaceManager As XmlNamespaceManager

        Public Function Xml() As String
            Return _xmlDoc.OuterXml
        End Function

        Public Sub New(certificateStr As String)
            RSAPKCS1SHA256SignatureDescription.Init()

            _certificate = New Certificate()
            _certificate.LoadCertificate(certificateStr)
        End Sub

        Public Sub New(certificateBytes As Byte())
            RSAPKCS1SHA256SignatureDescription.Init()

            _certificate = New Certificate()
            _certificate.LoadCertificate(certificateBytes)
        End Sub

        Public Sub LoadXml(xml As String)
            _xmlDoc = New XmlDocument()
            _xmlDoc.PreserveWhitespace = True
            _xmlDoc.XmlResolver = Nothing
            _xmlDoc.LoadXml(xml)
            _xmlNameSpaceManager = GetNamespaceManager()

        End Sub

        Public Sub LoadXmlFromBase64(response As String)
            Dim enc As UTF8Encoding = New UTF8Encoding
            LoadXml(enc.GetString(Convert.FromBase64String(response)))
        End Sub

        'Public Function IsValid() As Boolean
        '    Dim nodeList As XmlNodeList = _xmlDoc.SelectNodes("//ds:Signature", _xmlNameSpaceManager)
        '    Dim signedXml As SignedXml = New SignedXml(_xmlDoc)
        '    If nodeList.Count = 0 Then
        '        Return False
        '    End If
        '    signedXml.LoadXml(nodeList(0))
        '    Return ValidateSignatureReference(signedXml) AndAlso signedXml.CheckSignature(_certificate.cert, True) AndAlso IsExpired() = False
        'End Function

        'Private Function ValidateSignatureReference(signedXml As SignedXml) As Boolean
        '    If Not signedXml.SignedInfo.References.Count = 1 Then
        '        Return False
        '    End If
        '    Dim reference As Reference = signedXml.SignedInfo.References(0)
        '    Dim id = reference.Uri.Substring(1)

        '    Dim idElement As XmlElement = signedXml.GetIdElement(_xmlDoc, id)

        '    If idElement Is _xmlDoc.DocumentElement Then
        '        Return True
        '    Else
        '        Dim assertionNode As XmlElement = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion", _xmlNameSpaceManager)
        '        If Not idElement Is _xmlDoc.DocumentElement Then
        '            Return False
        '        End If
        '    End If

        '    Return True

        'End Function

        Private Function IsExpired() As Boolean
            Dim expirationDate = DateTime.MaxValue
            Dim node As XmlNode = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:Subject/saml:SubjectConfirmation/saml:SubjectConfirmationData", _xmlNameSpaceManager)
            If node IsNot Nothing AndAlso node.Attributes("NotOnOrAfter") IsNot Nothing Then
                DateTime.TryParse(node.Attributes("NotOnOrAfter").Value, expirationDate)
            End If
            Return DateTime.UtcNow > expirationDate.ToUniversalTime()
        End Function

        Public Function GetNameID() As String
            Dim node As XmlNode = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:Subject/saml:NameID", _xmlNameSpaceManager)
            Return node.InnerText
        End Function

        Public Function GetEmail() As String
            Dim node As XmlNode = _xmlDoc.SelectSingleNode("/samlp:Response/saml:Assertion[1]/saml:AttributeStatement/saml:Attribute[@Name='User.email']/saml:AttributeValue", _xmlNameSpaceManager)

            If node IsNot Nothing Then
                Return node.InnerText
            End If
            Return String.Empty
        End Function

        Private Function GetNamespaceManager() As XmlNamespaceManager
            Dim manager As XmlNamespaceManager = New XmlNamespaceManager(_xmlDoc.NameTable)
            ' manager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl)
            manager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion")
            manager.AddNamespace("samlp", "urn:oasis:names:tc:SAML:2.0:protocol")

            Return manager
        End Function
    End Class

    Public Class AuthRequest

        Public _id As String
        Private _issue_instant As String

        Private _issuer As String
        Private _assertionConsumerServiceUrl As String

        Public Enum AuthRequestFormat
            Base64 = 1
        End Enum

        Public Sub New(issuer As String, assertionConsumerServiceUrl As String)
            RSAPKCS1SHA256SignatureDescription.Init()

            _id = "_" + System.Guid.NewGuid().ToString()
            _issue_instant = DateTime.Now.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

            _issuer = issuer
            _assertionConsumerServiceUrl = assertionConsumerServiceUrl
        End Sub

        Public Function GetRequest(format As AuthRequestFormat) As String
            Using sw As New StringWriter()
                Dim xws = New XmlWriterSettings()
                xws.OmitXmlDeclaration = True
                Dim xw = XmlWriter.Create(sw, xws)

                xw.WriteStartElement("samlp", "AuthnRequest", "urn:oasis:names:tc:SAML:2.0:protocol")

                xw.WriteAttributeString("ID", _id)
                xw.WriteAttributeString("Version", "2.0")
                xw.WriteAttributeString("IssueInstant", _issue_instant)
                xw.WriteAttributeString("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")
                xw.WriteAttributeString("AssertionConsumerServiceURL", _assertionConsumerServiceUrl)

                xw.WriteStartElement("saml", "Issuer", "urn:oasis:names:tc:SAML:2.0:assertion")
                xw.WriteString(_issuer)
                xw.WriteEndElement()

                xw.WriteStartElement("samlp", "NameIDPolicy", "urn:oasis:names:tc:SAML:2.0:protocol")
                xw.WriteAttributeString("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
                xw.WriteAttributeString("AllowCreate", "true")
                xw.WriteEndElement()

                xw.WriteEndElement()

                If format = AuthRequestFormat.Base64 Then
                    Dim memoryStream = New MemoryStream()
                    Dim writer = New StreamWriter(New DeflateStream(memoryStream, CompressionMode.Compress, True), New UTF8Encoding(False))
                    writer.Write(sw.ToString())
                    writer.Close()
                    Dim result = Convert.ToBase64String(memoryStream.GetBuffer(), 0, memoryStream.Length, Base64FormattingOptions.None)
                    Return result

                End If
                Return Nothing
            End Using
        End Function

        Public Function GetRedirectUrl(samlEndpoint As String) As String
            Dim queryStringSeperator = IIf(samlEndpoint.Contains("?"), "&", "?")

            Return samlEndpoint + queryStringSeperator + "SAMLRequest=" + HttpUtility.UrlEncode(Me.GetRequest(AuthRequest.AuthRequestFormat.Base64))
        End Function

    End Class



End Namespace