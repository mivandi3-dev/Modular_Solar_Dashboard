// 4.0 (WT-15, AC-SRV-7): mutacijski fuzz pokretač bez libFuzzera (llvm-mingw ga ne isporučuje za mingw).
// Gradi se kao solari_fuzz; s -DSOLARI_SANITIZE=ON uz AddressSanitizer i UndefinedBehaviorSanitizer.
//   solari_fuzz [iteracije po meti, zadano 1000000] [sjeme] [meta]
// Za svaku metu: početni korpus (ispravni i granični ulazi) → mutacije (zamjena/umetanje/brisanje bajta, okretanje
// bita, zanimljive vrijednosti, spajanje s drugim ulazom). Rušenje ili nalaz sanitizera prekida proces (kod ≠ 0).
// Ispis: meta, broj ulaza, trajanje, broj ulaza koje je parser prihvatio (dokaz da mutacije dosežu dublje grane).
#include <windows.h>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "api_ipc.hpp"
#include "crypto.hpp"
#include "fronius.hpp"
#include "ipc.hpp"
#include "modbus.hpp"
#include "offgrid.hpp"
#include "poller.hpp"
#include "smartlogger_export.hpp"

using namespace sm;

namespace {

struct Rng {
    uint64_t s;
    uint64_t next() {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        return s;
    }
    size_t below(size_t n) { return n ? static_cast<size_t>(next() % n) : 0; }
};

std::string mutate(std::string in, const std::vector<std::string>& corpus, Rng& r, size_t max_len) {
    static const uint8_t interesting[] = {0x00, 0x01, 0x7F, 0x80, 0xFF, '{', '}', '[', ']', '"', '\\', ':', ',', '\r', '\n', '(', '0', '9', '-', 'e'};
    const int rounds = 1 + static_cast<int>(r.below(4));
    for (int i = 0; i < rounds; ++i) {
        switch (r.below(7)) {
        case 0:
            if (!in.empty()) in[r.below(in.size())] = static_cast<char>(r.next());
            break;
        case 1:
            if (!in.empty()) in[r.below(in.size())] ^= static_cast<char>(1u << r.below(8));
            break;
        case 2:
            if (in.size() < max_len) in.insert(in.begin() + static_cast<long>(r.below(in.size() + 1)), static_cast<char>(r.next()));
            break;
        case 3:
            if (!in.empty()) in.erase(r.below(in.size()), 1 + r.below(std::min<size_t>(8, in.size())));
            break;
        case 4:
            if (!in.empty()) in[r.below(in.size())] = static_cast<char>(interesting[r.below(sizeof interesting)]);
            break;
        case 5: {  // spajanje s drugim ulazom
            const std::string& other = corpus[r.below(corpus.size())];
            if (!other.empty()) {
                const size_t a = r.below(other.size());
                in.insert(r.below(in.size() + 1), other.substr(a, 1 + r.below(other.size() - a)));
            }
            break;
        }
        default: {  // ponavljanje dijela (dugi nizovi, duboko ugnježđivanje)
            if (!in.empty() && in.size() < max_len / 2) {
                const size_t a = r.below(in.size());
                const std::string piece = in.substr(a, 1 + r.below(std::min<size_t>(16, in.size() - a)));
                for (size_t k = 0, n = 1 + r.below(64); k < n && in.size() < max_len; ++k) in.insert(a, piece);
            }
            break;
        }
        }
    }
    if (in.size() > max_len) in.resize(max_len);
    return in;
}

struct Target {
    const char* name;
    std::vector<std::string> corpus;
    size_t max_len;
    std::function<bool(const std::string&)> run;  // true = ulaz prihvaćen (dublja grana)
};

std::string frame(const std::string& body) {
    const auto n = static_cast<uint32_t>(body.size());
    return std::string{static_cast<char>(n & 0xFF), static_cast<char>((n >> 8) & 0xFF), static_cast<char>((n >> 16) & 0xFF),
                       static_cast<char>(n >> 24)} + body;
}

std::vector<uint8_t> rtu(uint8_t unit, uint8_t fc, const std::vector<uint16_t>& words) {
    std::vector<uint8_t> f = {unit, fc, static_cast<uint8_t>(words.size() * 2)};
    for (uint16_t w : words) {
        f.push_back(static_cast<uint8_t>(w >> 8));
        f.push_back(static_cast<uint8_t>(w & 0xFF));
    }
    const uint16_t crc = modbus_crc(f.data(), f.size());
    f.push_back(static_cast<uint8_t>(crc & 0xFF));
    f.push_back(static_cast<uint8_t>(crc >> 8));
    return f;
}

std::vector<Target> targets() {
    std::vector<Target> t;
    t.push_back({"ipc_frame",
                 {frame(R"({"v":1,"nonce":"ab","type":"request","route":"ping","method":"GET","client_ip":"10.0.0.1"})"), frame("{}"),
                  frame("[1,2]"), std::string("\xFF\xFF\x00\x00", 4), frame(R"({"a":[[[[{"b":"A"}]]]]})")},
                 4096, [](const std::string& in) { return ipc::decode_frame(in, ipc::kMaxRequestBytes).status == ipc::DecodeStatus::Ok; }});
    t.push_back({"gateway_request",
                 {R"({"type":"request","route":"report","method":"GET","year":2026,"month":10,"token":"abc_DEF","client_ip":"192.168.1.5"})",
                  R"({"type":"request","route":"image","method":"GET","image":"logo","client_ip":"::1","cf_ip":"203.0.113.9"})",
                  R"({"type":"request","route":"login","method":"POST","client_ip":"127.0.0.1","body":"{\"email\":\"a@b.hr\"}"})"},
                 2048, [](const std::string& in) {
                     const json j = json::parse(in, nullptr, false);
                     return !j.is_discarded() && request_from_ipc(j).has_value();
                 }});
    {
        const auto ok = rtu(1, 3, {0x1234, 0xABCD, 0x0000});
        t.push_back({"modbus_rtu", {std::string(ok.begin(), ok.end()), std::string("\x01\x83\x02\xC0\xF1", 5)}, 300, [](const std::string& in) {
                         try {
                             return !parse_rtu_response(reinterpret_cast<const uint8_t*>(in.data()), in.size(), 3, 3).empty();
                         } catch (const std::exception&) {
                             return false;
                         }
                     }});
    }
    t.push_back({"voltronic_qpigs",
                 {"(230.0 50.0 230.0 50.0 0161 0119 003 360 26.70 000 100 0034 0000 000.0 00.00 00000 00010000 00 00 00000 010",
                  "(000.0 00.0 229.9 49.9 0390 0313 007 437 52.80 004 090 0038 0004 112.4 52.86 00000 00110110 00 00 00211 110"},
                 400, [](const std::string& in) { return parse_qpigs(in).has_value(); }});
    t.push_back({"vedirect",
                 {std::string("\r\nPID\t0xA053\r\nV\t26340\r\nI\t-1500\r\nPPV\t120\r\nChecksum\t") + '\x5f',
                  "\r\nV\t12800\r\nVPV\t0\r\nPPV\t0\r\nCS\t0\r\nH19\t1234\r\nChecksum\t\x00"},
                 2000, [](const std::string& in) { return !parse_vedirect(in).empty(); }});
    t.push_back({"fronius_json",
                 {R"({"Body":{"Data":{"Site":{"P_PV":5200.5,"P_Grid":-1200,"P_Load":-4000,"E_Day":12345,"E_Total":9876543},"Inverters":{"1":{"P":5200}}}}})",
                  R"({"Body":{"Data":{"Site":{"P_PV":null,"P_Grid":null}}}})"},
                 2048, [](const std::string& in) {
                     const json j = json::parse(in, nullptr, false);
                     if (j.is_discarded()) return false;
                     try {
                         parse_fronius_powerflow(j, true);
                         return true;
                     } catch (const std::exception&) {
                         return false;
                     }
                 }});
    {
        std::string emap(8, '\0');  // perfmg_day.emap: zaglavlje 8 B + zapisi 16 B (u16 uređaj, u16 KPI, u32 razdoblje, u32 vrijeme, i32)
        for (uint32_t i = 0; i < 8; ++i) {
            const uint16_t dev = i == 3 ? 0x1002 : 0x0002, kpi = i == 4 ? 0x3012 : 0x3011;
            const uint32_t period = 1, ts = 1'717'200'000u + i * 86400u;  // 00:00 UTC
            const int32_t v = i == 5 ? -1 : static_cast<int32_t>(59929 + i);
            emap.append(reinterpret_cast<const char*>(&dev), 2).append(reinterpret_cast<const char*>(&kpi), 2)
                .append(reinterpret_cast<const char*>(&period), 4).append(reinterpret_cast<const char*>(&ts), 4)
                .append(reinterpret_cast<const char*>(&v), 4);
        }
        t.push_back({"smartlogger_emap", {emap, std::string(64, '\0')}, 4096, [](const std::string& in) {
                         try {
                             return !parse_perfmg_day(in).empty();
                         } catch (const std::exception&) {
                             return false;
                         }
                     }});
    }
    t.push_back({"base64url_base32", {"QUJDREVG", "abc_DEF-xyz", "JBSWY3DPEHPK3PXP", "MZXW6YTBOI======"}, 256, [](const std::string& in) {
                     const bool a = from_base64url(in).has_value();
                     const bool b = from_base32(in).has_value();
                     return a || b;
                 }});
    t.push_back({"register_decode", {std::string("\x12\x34\xAB\xCD", 4), std::string(8, '\xFF')}, 16, [](const std::string& in) {
                     std::vector<uint16_t> words;
                     for (size_t i = 0; i + 1 < in.size(); i += 2) words.push_back(static_cast<uint16_t>((uint8_t(in[i]) << 8) | uint8_t(in[i + 1])));
                     if (words.empty()) return false;
                     for (const char* d : {"U16", "I16", "U32", "I32"}) {
                         const size_t need = d[1] == '1' ? 1 : 2;
                         if (words.size() >= need) decode(std::vector<uint16_t>(words.begin(), words.begin() + static_cast<long>(need)), d);
                     }
                     return true;
                 }});
    return t;
}

}  // namespace

int main(int argc, char** argv) {
    const long long iterations = argc > 1 ? std::atoll(argv[1]) : 1'000'000;
    Rng rng{argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 0x5EEDu};
    const std::string only = argc > 3 ? argv[3] : "";
    if (!rng.s) rng.s = 1;
    int ran = 0;
    for (auto& t : targets()) {
        if (!only.empty() && only != t.name) continue;
        ++ran;
        const auto start = std::chrono::steady_clock::now();
        long long accepted = 0;
        std::vector<std::string> pool = t.corpus;
        for (long long i = 0; i < iterations; ++i) {
            const std::string& base = pool[rng.below(pool.size())];
            std::string input = mutate(base, pool, rng, t.max_len);
            if (t.run(input)) {
                ++accepted;
                if (pool.size() < 256 && rng.below(64) == 0) pool.push_back(std::move(input));  // prihvaćeni ulazi šire korpus
            }
        }
        const double s = std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
        std::printf("%-18s %lld ulaza  %.1f s  prihvaćeno %lld  korpus %zu  -> bez rušenja\n", t.name, iterations, s, accepted, pool.size());
        std::fflush(stdout);
    }
    if (!ran) {
        std::printf("nepoznata meta: %s\n", only.c_str());
        return 2;
    }
    std::printf("FUZZ GOTOV: %d meta, %lld ulaza po meti, sjeme %llu\n", ran, iterations, static_cast<unsigned long long>(argc > 2 ? std::strtoull(argv[2], nullptr, 10) : 0x5EEDu));
    return 0;
}
