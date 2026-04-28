/**
 * UAF Mini Benchmark — 4 representative vulnerabilities
 *
 * S-01 [SIMPLE]         : Direct delete then dereference
 * M-06 [MEDIUM]         : shared_ptr / raw pointer scope mismatch
 * M-11 [MEDIUM]         : Lambda capture of deleted raw pointer
 * C-02 [COMPLEX]        : Observer pattern — deleted but still subscribed
 *
 * Compile: g++ -std=c++17 -pthread -fsanitize=address -o uaf_mini uaf_mini.cpp
 */

 #include <iostream>
 #include <string>
 #include <vector>
 #include <memory>
 #include <functional>
 #include <algorithm>
 
 // ─────────────────────────────────────────────
 // S-01: Direct delete then dereference [SIMPLE]
 // ─────────────────────────────────────────────
 void vuln_s01_direct_delete_deref() {
     std::cout << "[S-01] Direct delete then dereference\n";
 
     int* p = new int(42);
     delete p;
     std::cout << "  UAF read: " << *p << "\n";  // [S-01] UAF
 }
 
 // ─────────────────────────────────────────────
 // M-06: shared_ptr / raw pointer scope mismatch [MEDIUM]
 // ─────────────────────────────────────────────
 void vuln_m06_shared_raw_mix() {
     std::cout << "[M-06] shared_ptr / raw pointer scope mismatch\n";
 
     int* raw = nullptr;
     {
         auto sp = std::make_shared<int>(777);
         raw = sp.get();
     }
     // shared_ptr destroyed; raw is dangling
     std::cout << "  UAF read: " << *raw << "\n";  // [M-06] UAF
 }
 
 // ─────────────────────────────────────────────
 // M-11: Lambda capture of deleted raw pointer [MEDIUM]
 // ─────────────────────────────────────────────
 std::function<int()> make_dangling_lambda() {
     int* val = new int(9999);
     auto fn = [val]() { return *val; };  // captures raw pointer by value
     delete val;                           // freed before lambda is called
     return fn;
 }
 
 void vuln_m11_lambda_capture_uaf() {
     std::cout << "[M-11] Lambda capture of deleted pointer\n";
 
     auto fn = make_dangling_lambda();
     std::cout << "  UAF read: " << fn() << "\n";  // [M-11] UAF
 }
 
 // ─────────────────────────────────────────────
 // C-02: Observer deleted but still subscribed [COMPLEX]
 // ─────────────────────────────────────────────
 class Observer {
 public:
     int id;
     Observer(int i) : id(i) {}
     virtual void on_event(const std::string& e) {
         std::cout << "  Observer " << id << " got: " << e << "\n";
     }
 };
 
 class EventBus {
     std::vector<Observer*> subs_;
 public:
     void subscribe(Observer* o)   { subs_.push_back(o); }
     void unsubscribe(Observer* o) {
         subs_.erase(std::remove(subs_.begin(), subs_.end(), o), subs_.end());
     }
     void publish(const std::string& e) {
         for (auto* o : subs_) o->on_event(e);  // UAF if subscriber deleted
     }
 };
 
 void vuln_c02_observer_uaf() {
     std::cout << "[C-02] Observer deleted but still subscribed\n";
 
     EventBus bus;
     auto* obs1 = new Observer(1);
     auto* obs2 = new Observer(2);
     bus.subscribe(obs1);
     bus.subscribe(obs2);
 
     bus.publish("init");
 
     delete obs2;              // forgot to unsubscribe
     bus.publish("update");   // [C-02] UAF — obs2->on_event called on freed object
 
     delete obs1;
 }
 
 // ─────────────────────────────────────────────
 // main
 // ─────────────────────────────────────────────
 int main() {
     vuln_s01_direct_delete_deref();
     vuln_m06_shared_raw_mix();
     vuln_m11_lambda_capture_uaf();
     vuln_c02_observer_uaf();
     return 0;
 }