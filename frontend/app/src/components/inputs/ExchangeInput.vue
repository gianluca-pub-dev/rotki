<script lang="ts" setup>
const props = withDefaults(
  defineProps<{
    value?: string | null;
    dense?: boolean;
    showWithKeyOnly?: boolean;
  }>(),
  {
    value: null,
    showWithKeyOnly: false,
  },
);

const emit = defineEmits<{
  (e: 'input', value: string): void;
}>();

const vModel = useSimpleVModel(props, emit);

const { allExchanges, exchangesWithKey } = storeToRefs(useLocationStore());

const rootAttrs = useAttrs();
</script>

<template>
  <VAutocomplete
    v-model="vModel"
    outlined
    v-bind="rootAttrs"
    :items="showWithKeyOnly ? exchangesWithKey : allExchanges"
    :dense="dense"
    auto-select-first
    v-on="
      // eslint-disable-next-line vue/no-deprecated-dollar-listeners-api
      $listeners
    "
  >
    <template #selection="{ item, attrs, on }">
      <ExchangeDisplay
        :exchange="item"
        :class="`exchange__${item}`"
        :size="dense ? '1.125rem' : undefined"
        v-bind="attrs"
        v-on="on"
      />
    </template>
    <template #item="{ item, attrs, on }">
      <ExchangeDisplay
        :exchange="item"
        :class="`exchange__${item}`"
        v-bind="attrs"
        v-on="on"
      />
    </template>
  </VAutocomplete>
</template>
