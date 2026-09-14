// Runs the trained 16-8-3 MLP forward pass on-device.
// Plain arithmetic over the arrays in model_weights.h - no TFLite
// Micro runtime, no arena sizing, no op resolver. Deliberately kept
// dependency-free so it compiles the same way in Wokwi and on real
// hardware without needing ESP-IDF components.
#pragma once

#include <math.h>
#include "model_weights.h"

inline void modelPredict(const float input[MODEL_INPUT_SIZE], float outProbs[MODEL_OUTPUT_SIZE]) {
  float hidden[MODEL_HIDDEN_SIZE];
  for (int j = 0; j < MODEL_HIDDEN_SIZE; j++) {
    float sum = MODEL_B1[j];
    for (int i = 0; i < MODEL_INPUT_SIZE; i++) {
      sum += input[i] * MODEL_W1[i][j];
    }
    hidden[j] = sum > 0 ? sum : 0;  // ReLU
  }

  float logits[MODEL_OUTPUT_SIZE];
  for (int k = 0; k < MODEL_OUTPUT_SIZE; k++) {
    float sum = MODEL_B2[k];
    for (int j = 0; j < MODEL_HIDDEN_SIZE; j++) {
      sum += hidden[j] * MODEL_W2[j][k];
    }
    logits[k] = sum;
  }

  // Softmax
  float maxLogit = logits[0];
  for (int k = 1; k < MODEL_OUTPUT_SIZE; k++) {
    if (logits[k] > maxLogit) maxLogit = logits[k];
  }
  float sumExp = 0;
  for (int k = 0; k < MODEL_OUTPUT_SIZE; k++) {
    outProbs[k] = expf(logits[k] - maxLogit);
    sumExp += outProbs[k];
  }
  for (int k = 0; k < MODEL_OUTPUT_SIZE; k++) {
    outProbs[k] /= sumExp;
  }
}