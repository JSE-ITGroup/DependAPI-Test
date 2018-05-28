using System;
using System.Text;
using System.Reflection;
using System.Security.Cryptography;
using System.IO;
using System.Data;
using System.IO.Compression;

namespace DependApiTest
{
    class Program
    {

        static void Main(string[] args)
        {
            string UserName, Password, Participant;
            Console.WriteLine("Welcome;");

            Console.WriteLine("Enter login name;");
            UserName = Console.ReadLine();

            Console.WriteLine("Enter Password;");
            Password = Console.ReadLine();

            Console.WriteLine("Enter Participant Code;");
            Participant = Console.ReadLine();

            //UserName = "";
            //Password = "";
            //Participant = "";

            SessionID = Login(UserName, Password, Participant);
            GetListOperations();
        }

        /// <summary>         
        /// Create Middleware Object         
        /// Note that RDServer is a Service reference and is defined          
        /// in the programming environment (like Visual Studio)         
        /// and points to the URL for the Depend middle layer          
        /// </summary>         
        private static DependApiTest.RDServiceClient.RDServiceClient mid = new DependApiTest.RDServiceClient.RDServiceClient();
        //private static DependApiTest.RDServiceClient.RDServiceClient mid2 = new DependApiTest.RDServiceClient.RDServiceClient();

        /// <summary>         
        /// Return structure         
        /// </summary>         
        private static DependApiTest.RDServiceClient.ReturnInfo rt = new DependApiTest.RDServiceClient.ReturnInfo();
        //private static DependApiTest.RDServiceClient.ReturnInfo rt2 = new DependApiTest.RDServiceClient.ReturnInfo();
        /// <summary>         
        /// Session ID         
        /// </summary>         


        static string SessionID = String.Empty;
        /// <summary>         
        /// Login. Create the connection and get session         
        /// </summary>  

        private static string Login(string UserName, string Password, string Participant)
        {
            string sessionID = String.Empty;
            Console.WriteLine();
            try
            {
                /* Call actual login. password is sent in MD5 */
                rt = mid.DependLogin(out sessionID, UserName, ComputeMD5Hash(Password), Assembly.GetExecutingAssembly().GetName().Name + " Ver: " + Assembly.GetExecutingAssembly().GetName().Version.ToString(), Participant);
                if (rt.HasError) // lets see what server thinks about that    
                    Console.WriteLine(String.Format("Login error: {0}\r\n{1}", rt.ErrorInfo.ErrorReference, rt.ErrorInfo.ErrorText));

                else if (rt.IDInfo[6].IDType == "USER_WARN_REMAIN") //warning is returned if password needs to be changed
                {
                    string passReference = GenerateUniqueReference(); // reference for operation used for auditing

                    Console.WriteLine(String.Format("Please Change Your Password. You have:{0} trie(s)", rt.IDInfo[6].IDValue));
                    string response;
                    Console.WriteLine("To change password press 1");
                    response = Console.ReadLine();
                    if (response == "1")
                    {
                        Console.WriteLine("Please enter old password");
                        var oldpass = Console.ReadLine();
                        Console.WriteLine("Please enter new password");
                        var newpass = Console.ReadLine();
                        Console.WriteLine("Please verifiy new password");
                        var verifypass = Console.ReadLine();
                        if (newpass != verifypass)
                        {
                            Console.WriteLine("Please verifiy new password");
                            verifypass = Console.ReadLine();
                        }
                        else
                        {
                            ChangePass(passReference, oldpass, newpass, sessionID);

                        }
                    }
                }
                else
                    Console.WriteLine(String.Format("Login successful.\r\nSessionID:{0}", sessionID));
            }
            catch (Exception ex) //catch unexpected stuff that is not able to set "rt" (like network failure)     
            {
                Console.WriteLine(String.Format("Login exception:\r\n{0}", ex.Message));
            }
            finally
            {
                //always close once done.    
                //if (mid != null)
                //    mid.Close();
            }
            return sessionID;
        }

        private static void GetListOperations()
        {
            byte[] data;
            string schema;
            string function;
            //string function2;
            string parameter;

            function = "CFUNCTION_BROKER_POSITIONS"; // Function Names
            //function2 = "LIST_HOLDER.2";
            //function = "CFUNCTION_BROKER_NON_TRADE_TRANS";

            //parameter = "null,USD"; //Function Parameters
            //parameter = "2012-04-02,2012-04-04";
            parameter = "2017-11-30";

            Console.WriteLine("\r\n Processing operation " + function);

            try
            {
                //Console.ReadLine();

                /* call operation and fill dataset. output stream is ziped! */
                rt = mid.DataSetListZIP(out schema, out data, SessionID, function, 100, parameter);
               
                Console.ReadLine();

                if (rt.HasError) // lets see what server thinks about that
                {
                    Console.WriteLine(String.Format(function + " error: {0}\r\n{1}", rt.ErrorInfo.ErrorReference, rt.ErrorInfo.ErrorText));
                    Console.ReadLine();
                }

                else
                {
                    string reader = MyunZipDS(data, schema);

                    Console.Write(reader);
                    Console.WriteLine("...");
                    Console.ReadLine();
                }
            }

            catch (Exception ex) //catch unexpected stuff that is not able to set "rt" (like network failure)             
            {
                Console.WriteLine(String.Format(function + " exception:\r\n{0}", ex.Message));
            }
            finally
            {
                //always close once done.                 
                if (mid != null)
                    mid.Close();
            }
        }

        private static string ComputeMD5Hash(string input)
        {
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] hash = md5.ComputeHash(Encoding.ASCII.GetBytes(input));

            StringBuilder stringBuilder = new StringBuilder();
            foreach (byte b in hash)
                stringBuilder.AppendFormat("{0:x2}", b);

            return stringBuilder.ToString();
        }

        public static string MyunZipDS(byte[] bytes, string schema)
        {
            using (var msi = new MemoryStream(bytes))
            using (var mso = new MemoryStream())
            {
                using (var gs = new GZipStream(msi, CompressionMode.Decompress))
                {

                    CopyTo(gs, mso);
                }

                string ans = Encoding.GetEncoding("utf-8").GetString(mso.ToArray());

                return ans;
            }
        }
        public static void CopyTo(Stream src, Stream dest)
        {
            byte[] bytes = new byte[4096];

            int cnt;

            while ((cnt = src.Read(bytes, 0, bytes.Length)) != 0)
            {
                dest.Write(bytes, 0, cnt);
            }
        }

        private static bool ChangePass(string uniqueReference, string oldpass, string newpass, string sessionID)
        {
            //string sessionID = sessionID;

            byte[] bs;
            DataRow password;
            DataSet passwordDS = new DataSet("Password");
            Console.WriteLine("\r\nEnter Password: ");
            string schema;
            try
            {
                /* get schema */
                rt = mid.DataSetListZIP(out schema, out bs, sessionID, "P_CHANGE_PASSWORD.1", 0, null);
                if (rt.HasError) // lets see what server thinks about that                 
                {
                    Console.WriteLine(String.Format("Password schema retrieve error: {0}\r\n{1}", rt.ErrorInfo.ErrorReference, rt.ErrorInfo.ErrorText));
                    return false;
                }
                else
                {
                    passwordDS.ReadXmlSchema(new StringReader(schema));
                    Console.WriteLine(String.Format("Password schema retrieved."));
                }
            }
            catch (Exception ex) //catch unexpected stuff that is not able to set "rt" (like network failure)             
            {
                Console.WriteLine(String.Format("Account Status list exception:\r\n{0}", ex.Message));
                return false;
            }
            finally
            {
                //always close once done.             
                if (mid != null)
                    mid.Close();
            }
            password = passwordDS.Tables["P_CHANGE_PASSWORD"].NewRow();
            password["USER_OLD_PASSWORD"] = ComputeMD5Hash(oldpass);// "P@ssw0rd";
            password["USER_PASSWORD"] = ComputeMD5Hash(newpass); ; // "dr0wss@P1";

            passwordDS.Tables["P_CHANGE_PASSWORD"].Rows.Add(password);
            // insert password             
            int changedRows = 0;
            int auditID = 0;
            /* check if there is changed rows */
            if (passwordDS.Tables[0].GetChanges() != null)
                changedRows = passwordDS.Tables[0].GetChanges().Rows.Count;
            if (changedRows > 0)
                Console.WriteLine(String.Format("\r\nPosting {0} changed row(s) of password back to server... ", changedRows));
            else
            {
                Console.WriteLine("\r\nNothing to write to server");
                return false;
            }
            try
            {
                /* call actual update with user reference GenerateUniqueReference(). 
                server reference will be in auditID. Send changes only to reduce the load and optimize performance */
                rt = mid.DataSetUpdate(ref auditID, sessionID, "P_CHANGE_PASSWORD.1", 0, DataSetToXMLStr(passwordDS), uniqueReference);
                if (rt.HasError) // lets see what server thinks about that    
                {
                    Console.WriteLine(String.Format("Password post error: {0}\r\n{1} (audit ref:{2})", rt.ErrorInfo.ErrorReference, rt.ErrorInfo.ErrorText, uniqueReference));
                    return false;
                }
                else
                {
                    Console.WriteLine(String.Format("Password posted with auditID: {0} (audit ref:{1})", auditID, uniqueReference));
                }
            }
            catch (Exception ex)  //catch unexpected stuff that is not able to set "rt" (like network failure) 
            {
                Console.WriteLine(String.Format("Password table edit exception:\r\n{0}\r\n(audit ref:{1})", ex.Message, uniqueReference));
                return false;
            }
            finally
            {
                //always close once done.   
                if (mid != null)
                    mid.Close();
            }
            return true;
        }

        public static string DataSetToXMLStr(DataSet dsSrc)
        {
            DataSet ds = dsSrc.Copy();
            foreach (DataTable t in ds.Tables)
            {
                //add IUD     
                if (!t.Columns.Contains("IUD"))
                    t.Columns.Add("IUD", System.Type.GetType("System.String"));
                //remove not null   
                foreach (DataColumn c in t.Columns)
                    if (c.AllowDBNull == false)
                        c.AllowDBNull = true;
            }
            foreach (DataTable t in ds.Tables)
            {
                foreach (DataRow r in t.Rows)
                {
                    if (r.RowState == DataRowState.Unchanged)
                        continue;
                    switch (r.RowState)
                    {
                        case DataRowState.Added:
                            r["IUD"] = "I";
                            break;
                        case DataRowState.Modified:
                            r["IUD"] = "U";
                            break;
                        case DataRowState.Deleted:
                            r.RejectChanges();
                            r["IUD"] = "D";
                            break;
                        default:
                            break;
                    }
                }
            }
            //update parent records   
            foreach (DataTable t in ds.Tables)
            {
                if (t.ParentRelations.Count == 0)
                    continue;
                foreach (DataRelation rel in t.ParentRelations)
                {
                    foreach (DataColumn c in rel.ChildColumns)
                        if (!c.ExtendedProperties.ContainsKey("KEY"))
                            c.ExtendedProperties.Add("KEY", "Y");
                    foreach (DataColumn c in rel.ParentColumns)
                        if (!c.ExtendedProperties.ContainsKey("KEY"))
                            c.ExtendedProperties.Add("KEY", "Y");
                }
                foreach (DataRow r in t.Rows)
                {
                    if (r.RowState == DataRowState.Unchanged)
                        continue;
                    foreach (DataRelation rel in t.ParentRelations)
                    {
                        DataRow pr = r.GetParentRow(rel);
                        if (pr.RowState == DataRowState.Unchanged && pr["IUD"] == DBNull.Value)
                            pr["IUD"] = "N";
                    }
                }
            }
            foreach (DataTable t in ds.Tables)
            {
                foreach (DataRow r in t.Rows)
                {
                    if (r.RowState == DataRowState.Deleted)
                        continue;
                    if (r["IUD"] == DBNull.Value)
                    {
                        r.Delete();
                        continue;
                    }
                    if ((String)r["IUD"] == "D" || (String)r["IUD"] == "N")
                    {
                        foreach (DataColumn c in t.Columns)
                        {
                            if (c.ColumnName == "IUD")
                                continue;
                            if (c.ReadOnly)
                                c.ReadOnly = false;
                            if (!c.ExtendedProperties.ContainsKey("KEY"))
                                r[c] = DBNull.Value;
                        }
                        continue;
                    }
                }
            }
            //clear all readonly     
            foreach (DataTable t in ds.Tables)
            {
                foreach (DataColumn c in t.Columns)
                {
                    if (c.ReadOnly == false)
                        continue;
                    if (c.ExtendedProperties.ContainsKey("KEY"))
                        continue;
                    c.ReadOnly = false;
                    foreach (DataRow r in t.Rows)
                        if (r.RowState != DataRowState.Deleted)
                            r[c] = DBNull.Value;
                }
            }
            ds.AcceptChanges();
            return ds.GetXml();
        }

        public static string GenerateUniqueReference()
        {
            string str = Guid.NewGuid().ToString();
            str = str.Substring(str.Length - 20, 20);
            return str;
        }

    }
}
