using Org.BouncyCastle.Asn1;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ExtractPkey
{
    static class Asn1Utils
    {
        public static Asn1Encodable Goto(Asn1Encodable obj, string path)
        {
            Asn1Encodable cur = obj;
            string[] parts = path.Split('/');
            
            foreach (string part in parts) {
                var seq = cur as Asn1Sequence;
                if (seq == null) {
                    var tag = cur as Asn1TaggedObject;
                    if (tag != null) {
                        seq = tag.GetObject() as Asn1Sequence;
                    }
                }

                int index = Int32.Parse(part);
                if (seq != null && index >= 0 && seq.Count > index) {
                    cur = seq[index];
                } else {
                    throw new Asn1Exception(String.Format(
                        "Невозможно выполнить переход по индексу {0} в объекте {1}.", index, cur));
                }
            }

            return cur;
        }

        public static byte[] ExtractOctets(Asn1Encodable obj)
        {
            var tagObj = obj as Asn1TaggedObject;
            if (tagObj != null) {
                var str = tagObj.GetObject() as Asn1OctetString;
                if (str != null) {
                    return str.GetOctets();
                }
            }
            return new byte[0];
        }
    }
}
