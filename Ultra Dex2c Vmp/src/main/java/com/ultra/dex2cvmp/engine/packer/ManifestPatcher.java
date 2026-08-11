package com.ultra.dex2cvmp.engine.packer;

import bin.xml.decode.AXmlDecoder;
import bin.xml.decode.AXmlResourceParser;
import bin.xml.decode.XmlPullParser;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;

public class ManifestPatcher {
    public static boolean customApplication = false;
    public static String customApplicationName = "";
    public static String packageName = "";

    public static byte @NotNull [] parseManifest(byte[] manifestBytes, String proxyAppName) throws IOException {
        // Reset static state so repeated calls in the same process don't carry over
        // values from a previous APK.
        customApplication = false;
        customApplicationName = "";
        packageName = "";

        AXmlDecoder axml = AXmlDecoder.decode(new java.io.ByteArrayInputStream(manifestBytes));
        AXmlResourceParser parser = new AXmlResourceParser();
        parser.open(new ByteArrayInputStream(axml.getData()), axml.mTableStrings);
        boolean success = false;

        int type;
        while ((type = parser.next()) != XmlPullParser.END_DOCUMENT) {
            if (type != XmlPullParser.START_TAG)
                continue;
            if (parser.getName().equals("manifest")) {
                int size = parser.getAttributeCount();
                for (int i = 0; i < size; ++i) {
                    if (parser.getAttributeName(i).equals("package")) {
                        packageName = parser.getAttributeValue(i);
                    }
                }
            } else if (parser.getName().equals("application")) {
                int size = parser.getAttributeCount();
                int appCFAttrIdx = -1; // index of android:appComponentFactory to strip
                for (int i = 0; i < size; ++i) {
                    int resId = parser.getAttributeNameResource(i);
                    if (resId == 0x01010003) {
                        // android:name — replace value with ProxyApplication
                        customApplication = true;
                        customApplicationName = parser.getAttributeValue(i);
                        int index = axml.mTableStrings.getSize();
                        byte[] data = axml.getData();
                        int off = parser.currentAttributeStart + 20 * i;
                        off += 8;
                        writeInt(data, off, index);
                        off += 8;
                        writeInt(data, off, index);
                    } else if (resId == 0x0101021b
                            || "appComponentFactory".equals(parser.getAttributeName(i))) {
                        // android:appComponentFactory — mark for removal.
                        // Matched by resource ID (0x0101021b) OR by name string — the
                        // name fallback handles APKs where the binary manifest resource
                        // map is stripped/obfuscated (PairIP, some packers) and the
                        // parser returns 0 for the ID even though the attribute is present.
                        // Stripping it prevents CoreComponentFactory from firing and
                        // triggering "register dex with multiple class loaders".
                        appCFAttrIdx = i;
                    }
                }

                // Strip android:appComponentFactory if present
                if (appCFAttrIdx != -1) {
                    byte[] data = axml.getData();
                    int attrStart = parser.currentAttributeStart;
                    int removePos = attrStart + 20 * appCFAttrIdx;
                    byte[] stripped = new byte[data.length - 20];
                    System.arraycopy(data, 0, stripped, 0, removePos);
                    System.arraycopy(data, removePos + 20, stripped, removePos,
                            data.length - removePos - 20);
                    // chunkSize − 20
                    writeInt(stripped, attrStart - 32, readInt(stripped, attrStart - 32) - 20);
                    // attributeCount − 1
                    writeInt(stripped, attrStart - 8, size - 1);
                    size--;
                    axml.setData(stripped);
                }

                if (!customApplication) {
                    int off = parser.currentAttributeStart;
                    byte[] data = axml.getData();
                    byte[] newData = new byte[data.length + 20];
                    System.arraycopy(data, 0, newData, 0, off);
                    System.arraycopy(data, off, newData, off + 20, data.length - off);

                    // chunkSize
                    int chunkSize = readInt(newData, off - 32);
                    writeInt(newData, off - 32, chunkSize + 20);
                    // attributeCount
                    writeInt(newData, off - 8, size + 1);

                    int idIndex = parser.findResourceID(0x01010003);
                    if (idIndex == -1)
                        throw new IOException("idIndex == -1");

                    boolean isMax = true;
                    for (int i = 0; i < size; ++i) {
                        int id = parser.getAttributeNameResource(i);
                        if (id > 0x01010003) {
                            isMax = false;
                            if (i != 0) {
                                System.arraycopy(newData, off + 20, newData, off, 20 * i);
                                off += 20 * i;
                            }
                            break;
                        }
                    }
                    if (isMax) {
                        System.arraycopy(newData, off + 20, newData, off, 20 * size);
                        off += 20 * size;
                    }

                    writeInt(newData, off, axml.mTableStrings.find("http://schemas.android.com/apk/res/android"));
                    writeInt(newData, off + 4, idIndex);
                    writeInt(newData, off + 8, axml.mTableStrings.getSize());
                    writeInt(newData, off + 12, 0x03000008);
                    writeInt(newData, off + 16, axml.mTableStrings.getSize());
                    axml.setData(newData);
                }
                success = true;
                break;
            }
        }
        if (!success) {
            throw new IOException("failed to patch manifest");
        }
        ArrayList<String> list = new ArrayList<>(axml.mTableStrings.getSize());
        axml.mTableStrings.getStrings(list);
        list.add(proxyAppName);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        axml.write(list, baos);
        return baos.toByteArray();
    }

    private static void writeInt(byte @NotNull [] data, int off, int value) {
        data[off++] = (byte) (value & 0xFF);
        data[off++] = (byte) ((value >>> 8) & 0xFF);
        data[off++] = (byte) ((value >>> 16) & 0xFF);
        data[off] = (byte) ((value >>> 24) & 0xFF);
    }

    @Contract(pure = true)
    private static int readInt(byte @NotNull [] data, int off) {
        return data[off + 3] << 24 | (data[off + 2] & 0xFF) << 16 | (data[off + 1] & 0xFF) << 8
                | data[off] & 0xFF;
    }
}