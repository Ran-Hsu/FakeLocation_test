package com.xposed.hook.location;

import android.location.Criteria;
import android.location.Location;
import android.location.LocationManager;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.telephony.CellIdentityGsm;
import android.telephony.CellIdentityLte;
import android.telephony.CellIdentityNr;
import android.telephony.CellIdentityTdscdma;
import android.telephony.CellIdentityWcdma;
import android.telephony.TelephonyManager;
import android.telephony.gsm.GsmCellLocation;
import android.util.Log;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.Collections;

import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XC_MethodReplacement;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.XposedHelpers;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Created by lin on 2017/7/23.
 * Hardened for newer Android: pre-check classes/methods before hooking to avoid crashing target processes
 */

public class LocationHook {

    public static String TAG = "LocationHook";

    public static void hookAndChange(XC_LoadPackage.LoadPackageParam mLpp, final double latitude, final double longitude, final long lac, final long cid) {

        Log.d(TAG, "Avalon Hook Location Test: " + mLpp.packageName);
        LocationConfig.setLatitude(latitude);
        LocationConfig.setLongitude(longitude);

        // Use safe wrapper methods that verify class/method existence and guard with try/catch
        safeHookMethod(WifiManager.class, "getScanResults", XC_MethodReplacement.returnConstant(Collections.emptyList()));
        safeHookMethod(WifiInfo.class, "getMacAddress", XC_MethodReplacement.returnConstant("02:00:00:00:00:00"));
        safeHookMethod(WifiInfo.class, "getSSID", XC_MethodReplacement.returnConstant("<unknown ssid>"));
        safeHookMethod(WifiInfo.class, "getBSSID", XC_MethodReplacement.returnConstant("02:00:00:00:00:00"));

        safeHookMethods("android.location.LocationManager", "requestLocationUpdates", new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                LocationHandler.getInstance().start();
            }
        });

        safeHookMethod("android.location.LocationManager", mLpp.classLoader, "getLastLocation", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Location loc = (Location) param.getResult();
                if (loc != null)
                    LocationHandler.updateLocation(loc, LocationConfig.getLatitude(), LocationConfig.getLongitude());
                else
                    param.setResult(LocationHandler.createLocation(LocationConfig.getLatitude(), LocationConfig.getLongitude()));
            }
        });

        safeHookMethods("android.location.LocationManager", "getLastKnownLocation", new XC_MethodHook() {
            @Override
            protected void afterHookedMethod(MethodHookParam param) throws Throwable {
                Location loc = (Location) param.getResult();
                if (loc != null)
                    LocationHandler.updateLocation(loc, LocationConfig.getLatitude(), LocationConfig.getLongitude());
                else
                    param.setResult(LocationHandler.createLocation(LocationConfig.getLatitude(), LocationConfig.getLongitude()));
            }
        });

        safeHookMethod(Location.class, "getLatitude", new XC_MethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                return LocationConfig.getLatitude();
            }
        });
        safeHookMethod(Location.class, "getLongitude", new XC_MethodReplacement() {
            @Override
            protected Object replaceHookedMethod(MethodHookParam param) throws Throwable {
                return LocationConfig.getLongitude();
            }
        });

        safeHookMethod(LocationManager.class, "getBestProvider", Criteria.class, boolean.class, XC_MethodReplacement.returnConstant("gps"));
        safeHookMethod(LocationManager.class, "isProviderEnabled", String.class, new XC_MethodHook() {
            @Override
            protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
                Log.d(TAG, "isProviderEnabled: " + param.args[0]);
                if ("gps".equals(param.args[0]))
                    param.setResult(true);
            }
        });

        safeHookMethod(TelephonyManager.class, "getNeighboringCellInfo", XC_MethodReplacement.returnConstant(null));

        int ac = (int) lac;
        int ci = cid > Integer.MAX_VALUE ? -1 : (int) cid;

        safeHookMethod(GsmCellLocation.class, "getLac", XC_MethodReplacement.returnConstant(ac));
        safeHookMethod(GsmCellLocation.class, "getCid", XC_MethodReplacement.returnConstant(ci));

        // 2G
        safeHookMethod(CellIdentityGsm.class, "getLac", XC_MethodReplacement.returnConstant(ac));
        safeHookMethod(CellIdentityGsm.class, "getCid", XC_MethodReplacement.returnConstant(ci));

        // 3G
        safeHookMethod(CellIdentityWcdma.class, "getLac", XC_MethodReplacement.returnConstant(ac));
        safeHookMethod(CellIdentityWcdma.class, "getCid", XC_MethodReplacement.returnConstant(ci));

        // 4G
        safeHookMethod(CellIdentityLte.class, "getTac", XC_MethodReplacement.returnConstant(ac));
        safeHookMethod(CellIdentityLte.class, "getCi", XC_MethodReplacement.returnConstant(ci));

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P && classExists("android.telephony.CellIdentityTdscdma")) {
            safeHookMethod(CellIdentityTdscdma.class, "getLac", XC_MethodReplacement.returnConstant(ac));
            safeHookMethod(CellIdentityTdscdma.class, "getCid", XC_MethodReplacement.returnConstant(ci));
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q && classExists("android.telephony.CellIdentityNr")) {
            safeHookMethod(CellIdentityNr.class, "getTac", XC_MethodReplacement.returnConstant(ac));
            safeHookMethod(CellIdentityNr.class, "getNci", XC_MethodReplacement.returnConstant(cid));
        }
    }

    // Safe wrappers and helpers

    private static boolean classExists(String className) {
        try {
            Class.forName(className);
            return true;
        } catch (Throwable t) {
            Log.d(TAG, "Class not found: " + className + " -> " + t);
            return false;
        }
    }

    private static boolean methodExists(Class<?> clazz, String methodName, Class<?>... paramTypes) {
        try {
            clazz.getMethod(methodName, paramTypes);
            return true;
        } catch (Throwable t) {
            Log.d(TAG, "Method not found: " + clazz + "#" + methodName + " -> " + t);
            return false;
        }
    }

    // Wrapper for hooking methods on Class objects
    private static void safeHookMethod(Class<?> clazz, String methodName, Object... parameterTypesAndCallback) {
        if (clazz == null) {
            Log.d(TAG, "safeHookMethod: clazz is null for method " + methodName);
            return;
        }
        try {
            // Optional: check method existence if we can determine parameter types (best-effort)
            XposedHelpers.findAndHookMethod(clazz, methodName, parameterTypesAndCallback);
        } catch (Throwable e) {
            Log.d(TAG, "safeHookMethod failed for " + clazz.getName() + "#" + methodName + " -> " + e);
        }
    }

    // Wrapper for hooking methods by class name + ClassLoader
    private static void safeHookMethod(String className, ClassLoader classLoader, String methodName, Object... parameterTypesAndCallback) {
        if (className == null) return;
        try {
            Class<?> clazz = Class.forName(className, false, classLoader);
            if (clazz == null) {
                Log.d(TAG, "safeHookMethod: class not found by name: " + className);
                return;
            }
            XposedHelpers.findAndHookMethod(clazz, methodName, parameterTypesAndCallback);
        } catch (Throwable e) {
            Log.d(TAG, "safeHookMethod by name failed for " + className + "#" + methodName + " -> " + e);
        }
    }

    // Wrapper that only hooks if the named class is present in the boot/classloader
    private static void safeHookMethods(String className, String methodName, XC_MethodHook xmh) {
        try {
            if (!classExists(className)) {
                Log.d(TAG, "safeHookMethods: class " + className + " not present; skipping hook for " + methodName);
                return;
            }
            Class<?> clazz = Class.forName(className);
            for (Method method : clazz.getDeclaredMethods())
                if (method.getName().equals(methodName)
                        && !Modifier.isAbstract(method.getModifiers())
                        && Modifier.isPublic(method.getModifiers())) {
                    XposedBridge.hookMethod(method, xmh);
                }
        } catch (Throwable e) {
            Log.d(TAG, "safeHookMethods failed for " + className + "#" + methodName + " -> " + e);
        }
    }
}
