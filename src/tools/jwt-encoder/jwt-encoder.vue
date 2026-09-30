<script setup lang="ts">
import { ALGORITHM_DESCRIPTIONS } from '../jwt-parser/jwt-parser.constants';
import { JWT_ALGORITHMS, type JwtAlgorithm, encodeJwt, generateKeyPair, isSymmetricAlgorithm } from './jwt-encoder.service';
import { useCopy } from '@/composable/copy';
import { useValidation } from '@/composable/validation';
import { withDefaultOnError } from '@/utils/defaults';

const algorithm = ref<JwtAlgorithm>('HS256');
const rawHeader = ref(JSON.stringify({ alg: 'HS256', typ: 'JWT' }, null, 2));
const rawPayload = ref(JSON.stringify({ sub: '1234567890', name: 'John Doe', iat: 1516239022 }, null, 2));
const secret = ref('your-256-bit-secret');
const isSecretBase64Encoded = ref(false);
const privateKeyPem = ref('');
const generatedKeys = ref<{ privateKeyPem: string; publicKeyPem: string; keyType: string }>();
const isGeneratingKeys = ref(false);

const isSymmetric = computed(() => isSymmetricAlgorithm(algorithm.value));

const algorithmOptions = JWT_ALGORITHMS.map(value => ({ value, label: `${value} - ${ALGORITHM_DESCRIPTIONS[value]}` }));

function parseJsonObject(value: string) {
  const parsed = JSON.parse(value);

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('Not a JSON object');
  }

  return parsed as Record<string, unknown>;
}

const jsonObjectRules = [{ validator: (value: string) => parseJsonObject(value), message: 'Must be a valid JSON object' }];
const headerValidation = useValidation({ source: rawHeader, rules: jsonObjectRules });
const payloadValidation = useValidation({ source: rawPayload, rules: jsonObjectRules });

// RS* and PS* share RSA keys, each ES* needs a key on its own curve
function getKeyType(alg: JwtAlgorithm) {
  return alg.startsWith('ES') ? alg : 'RSA';
}

// The public key is only known for keys generated here, not for keys pasted by the user
const publicKeyPem = computed(() =>
  generatedKeys.value?.privateKeyPem === privateKeyPem.value ? generatedKeys.value.publicKeyPem : '',
);

async function generateKeys() {
  isGeneratingKeys.value = true;

  try {
    const keyType = getKeyType(algorithm.value);
    const keys = await generateKeyPair({ algorithm: algorithm.value });
    generatedKeys.value = { ...keys, keyType };
    privateKeyPem.value = keys.privateKeyPem;
  }
  finally {
    isGeneratingKeys.value = false;
  }
}

watch(algorithm, (newAlgorithm) => {
  const header = withDefaultOnError(() => parseJsonObject(rawHeader.value), undefined);

  if (header) {
    rawHeader.value = JSON.stringify({ ...header, alg: newAlgorithm }, null, 2);
  }

  if (isSymmetricAlgorithm(newAlgorithm)) {
    return;
  }

  // Like jwt.io, provide a working key pair out of the box, without ever replacing a key pasted by the user
  const isUsingGeneratedKey = publicKeyPem.value !== '';
  const isGeneratedKeyIncompatible = generatedKeys.value?.keyType !== getKeyType(newAlgorithm);

  if (privateKeyPem.value === '' || (isUsingGeneratedKey && isGeneratedKeyIncompatible)) {
    generateKeys();
  }
});

const result = computedAsync(
  async () => {
    if (!headerValidation.isValid || !payloadValidation.isValid) {
      return { token: '', error: '' };
    }

    try {
      const token = await encodeJwt({
        header: parseJsonObject(rawHeader.value),
        payload: parseJsonObject(rawPayload.value),
        algorithm: algorithm.value,
        secret: secret.value,
        isSecretBase64Encoded: isSecretBase64Encoded.value,
        privateKeyPem: privateKeyPem.value,
      });

      return { token, error: '' };
    }
    catch (error) {
      return { token: '', error: error instanceof Error ? error.message : String(error) };
    }
  },
  { token: '', error: '' },
);

const tokenParts = computed(() => {
  const [header = '', payload = '', signature = ''] = result.value.token.split('.');
  return { header, payload, signature };
});

const token = computed(() => result.value.token);
const { copy } = useCopy({ source: token, text: 'JWT copied to the clipboard' });
</script>

<template>
  <div flex flex-col gap-4>
    <c-card title="Algorithm">
      <c-select v-model:value="algorithm" :options="algorithmOptions" searchable />
    </c-card>

    <c-card title="Header">
      <c-input-text v-model:value="rawHeader" :validation="headerValidation" rows="4" raw-text autosize multiline monospace />
    </c-card>

    <c-card title="Payload">
      <c-input-text v-model:value="rawPayload" :validation="payloadValidation" multiline raw-text rows="6" autosize monospace />
    </c-card>

    <c-card v-if="algorithm !== 'none'" title="Signature">
      <template v-if="isSymmetric">
        <c-input-text v-model:value="secret" label="Secret" placeholder="Enter the secret..." raw-text clearable mb-2 />
        <n-checkbox v-model:checked="isSecretBase64Encoded">
          Secret base64 encoded
        </n-checkbox>
      </template>

      <template v-else>
        <c-input-text
          v-model:value="privateKeyPem"
          label="Private key (PEM, PKCS#8 or PKCS#1)"
          placeholder="-----BEGIN PRIVATE KEY-----"
          multiline raw-text rows="8" monospace mb-3
        />

        <div mb-3 flex justify-center>
          <c-button :loading="isGeneratingKeys" @click="generateKeys()">
            Generate a new key pair
          </c-button>
        </div>

        <input-copyable
          v-if="publicKeyPem"
          :value="publicKeyPem"
          label="Public key (to verify the signature)"
          rows="6" multiline raw-text monospace readonly
        />
      </template>
    </c-card>

    <c-card title="Encoded JWT">
      <c-alert v-if="result.error" type="error">
        {{ result.error }}
      </c-alert>

      <template v-else-if="result.token">
        <div class="token" mb-4 font-mono>
          <span class="token-header">{{ tokenParts.header }}</span>.<span class="token-payload">{{ tokenParts.payload }}</span>.<span class="token-signature">{{ tokenParts.signature }}</span>
        </div>

        <div flex justify-center>
          <c-button @click="copy()">
            Copy JWT
          </c-button>
        </div>
      </template>

      <div v-else op-70>
        Fix the header and payload to generate the token.
      </div>
    </c-card>
  </div>
</template>

<style lang="less" scoped>
.token {
  word-break: break-all;
  line-height: 1.6;
}

// Same colors as jwt.io
.token-header {
  color: #fb015b;
}

.token-payload {
  color: #d63aff;
}

.token-signature {
  color: #00b9f1;
}
</style>
