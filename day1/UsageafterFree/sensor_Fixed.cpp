
#include <iostream>

class SensorData {
public:
    int temperature;

    SensorData(int temp) : temperature(temp) {
        std::cout << "SensorData created with temperature: " << temperature << std::endl;
    }

    void printTemperature() {
        std::cout << "Current temperature: " << temperature << std::endl;
    }

    ~SensorData() {
        std::cout << "SensorData object destroyed!" << std::endl;
    }
};

void processData(SensorData* data) {
    // Simulate processing data
    if (data) {
        data->printTemperature();
    } else {
        std::cout << "Invalid SensorData pointer." << std::endl;
    }
}

int main() {
    SensorData* sensor1 = new SensorData(25);
    processData(sensor1);
    delete sensor1;
    sensor1 = nullptr; // Set to nullptr after deletion

    SensorData* sensor2 = new SensorData(15);
    processData(sensor2); // Corrected to process sensor2
    delete sensor2;
    sensor2 = nullptr; // Set to nullptr after deletion

    return 0;
}
