#include <jni.h>

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

#if defined(__clang__)
#define PURE_AMICE_VMP __attribute__((annotate("+vm_virtualize")))
#define PURE_AMICE_MBA __attribute__((annotate("+split_basic_block,+split_basic_block_num=1,+mba")))
#else
#define PURE_AMICE_VMP
#define PURE_AMICE_MBA
#endif

namespace {

struct Profile {
    int width;
    int height;
    int crf;
    int max_rate_k;
    int clip_seconds;
};

struct ScopedUtf {
    JNIEnv *env;
    jstring value;
    const char *chars;

    ScopedUtf(JNIEnv *env, jstring value)
        : env(env), value(value), chars(value ? env->GetStringUTFChars(value, nullptr) : nullptr) {}

    ~ScopedUtf() {
        if (chars != nullptr) env->ReleaseStringUTFChars(value, chars);
    }

    std::string str() const { return chars == nullptr ? std::string() : std::string(chars); }
};

void throwIllegalArgument(JNIEnv *env, const char *message) {
    jclass exception = env->FindClass("java/lang/IllegalArgumentException");
    if (exception != nullptr) env->ThrowNew(exception, message);
}

std::string stringValue(JNIEnv *env, jstring value) {
    return ScopedUtf(env, value).str();
}

std::vector<std::string> stringArrayValue(JNIEnv *env, jobjectArray values) {
    std::vector<std::string> result;
    if (values == nullptr) return result;
    const jsize size = env->GetArrayLength(values);
    result.reserve(static_cast<size_t>(size));
    for (jsize i = 0; i < size; ++i) {
        auto value = static_cast<jstring>(env->GetObjectArrayElement(values, i));
        result.push_back(stringValue(env, value));
        env->DeleteLocalRef(value);
    }
    return result;
}

std::vector<double> doubleArrayValue(JNIEnv *env, jdoubleArray values) {
    std::vector<double> result;
    if (values == nullptr) return result;
    const jsize size = env->GetArrayLength(values);
    result.resize(static_cast<size_t>(size));
    if (size > 0) {
        env->GetDoubleArrayRegion(values, 0, size, result.data());
    }
    return result;
}

jobjectArray toStringArray(JNIEnv *env, const std::vector<std::string> &values) {
    jclass stringClass = env->FindClass("java/lang/String");
    if (stringClass == nullptr) return nullptr;
    jobjectArray result = env->NewObjectArray(static_cast<jsize>(values.size()), stringClass, nullptr);
    if (result == nullptr) return nullptr;
    for (jsize i = 0; i < static_cast<jsize>(values.size()); ++i) {
        jstring value = env->NewStringUTF(values[static_cast<size_t>(i)].c_str());
        if (value == nullptr) return nullptr;
        env->SetObjectArrayElement(result, i, value);
        env->DeleteLocalRef(value);
    }
    return result;
}

jintArray toIntArray(JNIEnv *env, const std::vector<int> &values) {
    jintArray result = env->NewIntArray(static_cast<jsize>(values.size()));
    if (result == nullptr) return nullptr;
    if (!values.empty()) {
        env->SetIntArrayRegion(result, 0, static_cast<jsize>(values.size()), values.data());
    }
    return result;
}

std::string formatDecimal(double value, int precision) {
    if (!std::isfinite(value)) value = 0.0;
    std::ostringstream stream;
    stream << std::fixed << std::setprecision(precision) << value;
    std::string result = stream.str();
    while (result.size() > 1 && result.back() == '0') result.pop_back();
    if (!result.empty() && result.back() == '.') result.pop_back();
    if (result == "-0") result = "0";
    return result;
}

std::string seconds(double value) {
    return formatDecimal(value, 3);
}

std::string general(double value) {
    return formatDecimal(value, 6);
}

double clamp01(double value) {
    return std::max(0.0, std::min(1.0, value));
}

double parseOr(double value, double fallback) {
    return std::isfinite(value) ? value : fallback;
}

double parseTextOr(const std::string &value, double fallback) {
    if (value.empty()) return fallback;
    char *end = nullptr;
    const double parsed = std::strtod(value.c_str(), &end);
    return end != value.c_str() && std::isfinite(parsed) ? parsed : fallback;
}

int parseIntTextOr(const std::string &value, int fallback) {
    if (value.empty()) return fallback;
    char *end = nullptr;
    const long parsed = std::strtol(value.c_str(), &end, 10);
    return end != value.c_str() ? static_cast<int>(parsed) : fallback;
}

PURE_AMICE_VMP Profile profileFor(int quality_ordinal, bool has_recipe) {
    if (quality_ordinal == 1 && has_recipe) {
        return {1080, 1920, 23, 3800, 29};
    }
    if (quality_ordinal == 0) {
        return {1080, 1920, 23, 3800, 29};
    }
    if (quality_ordinal == 1) {
        return {720, 1280, 24, 2200, 59};
    }
    return {1080, 1920, 25, 1200, 89};
}

PURE_AMICE_MBA int durationAwareBufsize(int max_rate_k, double duration) {
    double factor;
    if (duration < 6.0) {
        factor = 0.5;
    } else if (duration < 11.0) {
        factor = 1.0 / 1.5;
    } else if (duration < 16.0) {
        factor = 1.0;
    } else {
        factor = 1.5;
    }
    return std::max(1, static_cast<int>(std::lround(max_rate_k * factor)));
}

std::string baseFilter(
    const Profile &profile,
    const std::vector<double> &crop,
    bool hdr
) {
    std::string result;
    if (hdr) {
        result += "zscale=t=linear:npl=100,format=gbrpf32le,zscale=p=bt709,";
        result += "tonemap=tonemap=hable:desat=0,zscale=t=bt709:m=bt709:r=tv,setsar=1,";
    }
    if (crop.size() == 4) {
        result += "crop=trunc(iw*" + general(clamp01(crop[2])) + "/2)*2:";
        result += "trunc(ih*" + general(clamp01(crop[3])) + "/2)*2:";
        result += "trunc(iw*" + general(clamp01(crop[0])) + "/2)*2:";
        result += "trunc(ih*" + general(clamp01(crop[1])) + "/2)*2,";
    }
    result += "scale=w=" + std::to_string(profile.width);
    result += ":h=" + std::to_string(profile.height);
    result += ":force_original_aspect_ratio=decrease,";
    if (crop.size() != 4) {
        result += "pad=" + std::to_string(profile.width) + ":";
        result += std::to_string(profile.height) + ":(ow-iw)/2:(oh-ih)/2,";
    }
    result += "scale=trunc(iw/2)*2:trunc(ih/2)*2";
    return result;
}

std::string audioGraph(
    const std::string &audio_start_text,
    const std::string &audio_end_text,
    const std::string &music_volume_text,
    const std::string &original_volume_text,
    bool audio_fit_trim,
    bool audio_mix,
    bool source_audio,
    double duration,
    int audio_index
) {
    const double start = std::max(0.0, parseTextOr(audio_start_text, 0.0));
    const double end = std::max(
        start + 0.05,
        parseTextOr(audio_end_text, start + duration)
    );
    const double music_volume = std::max(
        0.0,
        std::min(100.0, static_cast<double>(parseIntTextOr(music_volume_text, 100)))
    ) / 100.0;
    const double original_volume = std::max(
        0.0,
        std::min(100.0, static_cast<double>(parseIntTextOr(original_volume_text, 35)))
    ) / 100.0;

    std::string result = "[" + std::to_string(audio_index) + ":a]atrim=start=";
    result += general(start) + ":end=" + general(end);
    result += ",asetpts=PTS-STARTPTS,";
    if (audio_fit_trim) {
        result += "apad=pad_dur=" + general(duration);
        result += ",atrim=duration=" + general(duration);
    } else {
        result += "aloop=loop=-1:size=2000000000,atrim=duration=";
        result += general(duration) + ",asetpts=PTS-STARTPTS";
    }
    result += ",volume=" + general(music_volume) + "[music]";

    if (!audio_mix || !source_audio) {
        return result + ";[music]anull[aout]";
    }

    result += ";[0:a]atrim=duration=" + general(duration);
    result += ",asetpts=PTS-STARTPTS,volume=" + general(original_volume);
    result += "[original];[original][music]amix=inputs=2:duration=longest:";
    result += "dropout_transition=0[aout]";
    return result;
}

std::vector<std::string> encodeOptions(const Profile &profile, double duration) {
    const int bufsize = durationAwareBufsize(profile.max_rate_k, duration);
    return {
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-color_range", "tv",
        "-color_primaries", "bt709", "-color_trc", "bt709", "-colorspace", "bt709",
        "-crf", std::to_string(profile.crf), "-maxrate", std::to_string(profile.max_rate_k) + "k",
        "-bufsize", std::to_string(bufsize) + "k", "-g", "250", "-profile:v", "high",
        "-level:v", "4.0", "-x264-params", "sei=0", "-r", "29.97",
        "-c:a", "aac", "-ar", "44100", "-ac", "2", "-b:a", "128k",
        "-brand", "isom", "-movflags", "+faststart", "-f", "mp4", "-threads", "2",
        "-t", seconds(duration),
    };
}

std::vector<std::string> buildVideoArgs(
    const std::string &source,
    const std::string &audio,
    bool has_audio_path,
    bool has_source_audio,
    int quality_ordinal,
    bool has_recipe,
    const std::vector<double> &crop,
    bool hdr,
    double source_start,
    double duration,
    const std::vector<std::string> &overlay_paths,
    const std::vector<double> &overlay_x,
    const std::vector<double> &overlay_y,
    const std::vector<double> &overlay_scale,
    const std::vector<double> &overlay_rotation,
    const std::string &audio_start_text,
    const std::string &audio_end_text,
    const std::string &music_volume_text,
    const std::string &original_volume_text,
    bool audio_fit_trim,
    bool audio_mix,
    const std::string &output
) {
    const Profile profile = profileFor(quality_ordinal, has_recipe);
    std::vector<std::string> args = {
        "-y", "-ss", seconds(source_start), "-t", seconds(duration), "-i", source,
    };
    for (const auto &overlay : overlay_paths) {
        args.insert(args.end(), {"-loop", "1", "-i", overlay});
    }
    if (has_audio_path) {
        args.insert(args.end(), {"-stream_loop", "-1", "-i", audio});
    }

    const std::string base = baseFilter(profile, crop, hdr);
    const int audio_index = 1 + static_cast<int>(overlay_paths.size());
    if (overlay_paths.empty() && !has_audio_path) {
        args.insert(args.end(), {"-vf", base, "-map", "0:v:0", "-map", "0:a?"});
    } else {
        std::string graph = "[0:v]" + base + "[v0]";
        std::string current = "v0";
        for (size_t index = 0; index < overlay_paths.size(); ++index) {
            const std::string scaled = "ov" + std::to_string(index);
            const std::string next = "v" + std::to_string(index + 1);
            const double scale = std::max(
                0.1,
                std::min(5.0, index < overlay_scale.size() ? overlay_scale[index] : 1.0)
            );
            const double radians = (index < overlay_rotation.size() ? overlay_rotation[index] : 0.0)
                * 0.017453292519943295;
            const double x = std::max(
                0.0,
                std::min(1.0, index < overlay_x.size() ? overlay_x[index] : 0.5)
            );
            const double y = std::max(
                0.0,
                std::min(1.0, index < overlay_y.size() ? overlay_y[index] : 0.5)
            );
            graph += ";[" + std::to_string(index + 1) + ":v]scale=iw*";
            graph += general(scale) + ":ih*" + general(scale);
            graph += ",rotate=" + general(radians) + ":ow=rotw(" + general(radians);
            graph += "):oh=roth(" + general(radians) + "):c=none[" + scaled + "]";
            graph += ";[" + current + "][" + scaled + "]overlay=x=(W*";
            graph += general(x) + ")-(w/2):y=(H*" + general(y) + ")-(h/2)[" + next + "]";
            current = next;
        }
        if (has_audio_path) {
            graph += ";" + audioGraph(
                audio_start_text,
                audio_end_text,
                music_volume_text,
                original_volume_text,
                audio_fit_trim,
                audio_mix,
                has_source_audio,
                duration,
                audio_index
            );
            args.insert(args.end(), {
                "-filter_complex", graph, "-map", "[" + current + "]", "-map", "[aout]",
            });
        } else {
            args.insert(args.end(), {
                "-filter_complex", graph, "-map", "[" + current + "]", "-map", "0:a?",
            });
        }
    }

    const auto options = encodeOptions(profile, duration);
    args.insert(args.end(), options.begin(), options.end());
    args.push_back(output);
    return args;
}

int parseRateK(const std::string &value, int fallback) {
    std::string normalized = value;
    if (normalized.size() > 1 && normalized.back() == 'k') normalized.pop_back();
    return parseIntTextOr(normalized, fallback);
}

PURE_AMICE_VMP int retryCrfBump(int attempt) {
    if (attempt == 1) return 1;
    if (attempt == 2) return 3;
    return attempt * 2;
}

int nativeMaxSizeAttemptsValue() {
    return 3;
}

std::vector<std::string> tighten(
    const std::vector<std::string> &arguments,
    int attempt,
    double duration,
    bool allow_720_rescue
) {
    std::vector<std::string> tightened = arguments;
    auto findOption = [&tightened](const std::string &option) -> int {
        for (size_t i = 0; i + 1 < tightened.size(); ++i) {
            if (tightened[i] == option) return static_cast<int>(i);
        }
        return -1;
    };

    const int crf_index = findOption("-crf");
    const int base_crf = crf_index >= 0 ? parseIntTextOr(tightened[crf_index + 1], 23) : 23;
    if (crf_index >= 0) {
        tightened[static_cast<size_t>(crf_index + 1)] =
            std::to_string(std::min(35, base_crf + retryCrfBump(attempt)));
    }

    const int max_rate_index = findOption("-maxrate");
    if (max_rate_index >= 0) {
        const int base_rate = parseRateK(tightened[max_rate_index + 1], 3800);
        const double factor = attempt == 1 ? 0.9 : (attempt == 2 ? 0.72 : std::pow(0.72, attempt));
        const int max_rate = std::max(800, static_cast<int>(std::lround(base_rate * factor)));
        tightened[static_cast<size_t>(max_rate_index + 1)] = std::to_string(max_rate) + "k";
        const int buffer_index = findOption("-bufsize");
        if (buffer_index >= 0) {
            tightened[static_cast<size_t>(buffer_index + 1)] =
                std::to_string(durationAwareBufsize(max_rate, duration)) + "k";
        }
    }

    bool has_size = false;
    for (const auto &value : tightened) {
        if (value == "-s:v") {
            has_size = true;
            break;
        }
    }
    if (allow_720_rescue && attempt >= nativeMaxSizeAttemptsValue() - 1 && !has_size) {
        tightened.insert(tightened.end(), {"-s:v", "720x1280"});
    }
    return tightened;
}

}  // namespace

extern "C" JNIEXPORT jintArray JNICALL
Java_com_pure_status_pro_service_NativeMediaPolicy_nativeProfile(
    JNIEnv *env,
    jobject,
    jint quality_ordinal,
    jboolean has_recipe
) {
    const Profile profile = profileFor(quality_ordinal, has_recipe == JNI_TRUE);
    return toIntArray(env, {profile.clip_seconds});
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_pure_status_pro_service_NativeMediaPolicy_nativeBuildVideoArguments(
    JNIEnv *env,
    jobject,
    jstring source_path,
    jstring audio_path,
    jboolean has_source_audio,
    jint quality_ordinal,
    jboolean has_recipe,
    jdoubleArray crop,
    jboolean hdr,
    jdouble source_start,
    jdouble duration,
    jobjectArray overlay_paths,
    jdoubleArray overlay_x,
    jdoubleArray overlay_y,
    jdoubleArray overlay_scale,
    jdoubleArray overlay_rotation,
    jstring audio_start_text,
    jstring audio_end_text,
    jstring music_volume_text,
    jstring original_volume_text,
    jboolean audio_fit_trim,
    jboolean audio_mix,
    jstring output_path
) {
    const auto paths = stringArrayValue(env, overlay_paths);
    const auto xs = doubleArrayValue(env, overlay_x);
    const auto ys = doubleArrayValue(env, overlay_y);
    const auto scales = doubleArrayValue(env, overlay_scale);
    const auto rotations = doubleArrayValue(env, overlay_rotation);
    if (xs.size() != paths.size() || ys.size() != paths.size() ||
        scales.size() != paths.size() || rotations.size() != paths.size()) {
        throwIllegalArgument(env, "Native media policy overlay arrays are inconsistent.");
        return nullptr;
    }

    return toStringArray(env, buildVideoArgs(
        stringValue(env, source_path),
        stringValue(env, audio_path),
        audio_path != nullptr,
        has_source_audio == JNI_TRUE,
        quality_ordinal,
        has_recipe == JNI_TRUE,
        doubleArrayValue(env, crop),
        hdr == JNI_TRUE,
        parseOr(source_start, 0.0),
        std::max(0.1, parseOr(duration, 0.1)),
        paths,
        xs,
        ys,
        scales,
        rotations,
        stringValue(env, audio_start_text),
        stringValue(env, audio_end_text),
        stringValue(env, music_volume_text),
        stringValue(env, original_volume_text),
        audio_fit_trim == JNI_TRUE,
        audio_mix == JNI_TRUE,
        stringValue(env, output_path)
    ));
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_pure_status_pro_service_NativeMediaPolicy_nativeBuildPhotoArguments(
    JNIEnv *env,
    jobject,
    jstring source_path,
    jstring output_path
) {
    return toStringArray(env, {
        "-y", "-loop", "1", "-framerate", "25", "-i", stringValue(env, source_path),
        "-t", "5", "-frames:v", "125",
        "-vf", "scale=720:1280:force_original_aspect_ratio=decrease:flags=lanczos,"
                "pad=720:1280:(ow-iw)/2:(oh-ih)/2:color=black,setsar=1,format=yuv420p",
        "-c:v", "libx264", "-preset", "veryfast", "-crf", "23", "-r", "25",
        "-an", "-movflags", "+faststart", stringValue(env, output_path),
    });
}

extern "C" JNIEXPORT jobjectArray JNICALL
Java_com_pure_status_pro_service_NativeMediaPolicy_nativeTightenForSizeRetry(
    JNIEnv *env,
    jobject,
    jobjectArray arguments,
    jint attempt,
    jdouble duration,
    jboolean allow_720_rescue
) {
    return toStringArray(env, tighten(
        stringArrayValue(env, arguments),
        std::max(1, static_cast<int>(attempt)),
        parseOr(duration, 0.1),
        allow_720_rescue == JNI_TRUE
    ));
}

extern "C" JNIEXPORT jdouble JNICALL
Java_com_pure_status_pro_service_NativeMediaPolicy_nativeLongClipRetryThresholdSeconds(
    JNIEnv *,
    jobject
) {
    return 59.0;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_pure_status_pro_service_NativeMediaPolicy_nativeAllow720Rescue(
    JNIEnv *,
    jobject,
    jint quality_ordinal,
    jboolean has_recipe
) {
    const Profile profile = profileFor(quality_ordinal, has_recipe == JNI_TRUE);
    return profile.width == 1080 && profile.height == 1920 ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_pure_status_pro_service_NativeMediaPolicy_nativeIsHdrVideo(
    JNIEnv *,
    jobject,
    jint standard,
    jint primaries,
    jint transfer
) {
    // Android MediaFormat values: BT.2020 standard=6, BT.2020 primaries=9,
    // SMPTE ST 2084 transfer=6, and HLG transfer=7.
    return standard == 6 || primaries == 9 || transfer == 6 || transfer == 7
        ? JNI_TRUE
        : JNI_FALSE;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_pure_status_pro_service_NativeMediaPolicy_nativeMaxDeliveryClips(JNIEnv *, jobject) {
    return 20;
}

extern "C" JNIEXPORT jlong JNICALL
Java_com_pure_status_pro_service_NativeMediaPolicy_nativeMaxClipBytes(JNIEnv *, jobject) {
    return 15800000L;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_pure_status_pro_service_NativeMediaPolicy_nativeMaxSizeAttempts(JNIEnv *, jobject) {
    return nativeMaxSizeAttemptsValue();
}