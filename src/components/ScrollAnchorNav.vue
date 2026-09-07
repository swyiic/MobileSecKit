<template>
  <Transition name="anchor-nav">
    <nav v-if="visible" class="scroll-anchor-nav" aria-label="当前页面快捷导航">
      <button
        v-for="anchor in anchors"
        :key="anchor.id"
        type="button"
        :class="{ active: activeId === anchor.id }"
        :title="`跳转到 ${anchor.label}`"
        @click="navigate(anchor.id)"
      >
        <i></i><span>{{ anchor.label }}</span>
      </button>
    </nav>
  </Transition>
</template>

<script setup lang="ts">
import { toRef } from 'vue'
import { useScrollAnchors, type ScrollAnchor } from '@/composables/useScrollAnchors'

const props = withDefaults(defineProps<{ anchors: ScrollAnchor[]; revealAfter?: number }>(), { revealAfter: 420 })
const emit = defineEmits<{ navigate: [id: string] }>()
const { visible, activeId, scrollToAnchor } = useScrollAnchors(toRef(props, 'anchors'), props.revealAfter)

function navigate(id: string) {
  emit('navigate', id)
  void scrollToAnchor(id)
}
</script>

<style scoped>
.scroll-anchor-nav{position:fixed;z-index:35;top:50%;right:18px;display:grid;gap:3px;max-width:154px;padding:6px;border:1px solid rgba(100,145,210,.18);border-radius:11px;background:rgba(8,13,21,.88);box-shadow:0 12px 38px rgba(0,0,0,.3);backdrop-filter:blur(14px);transform:translateY(-50%)}
.scroll-anchor-nav button{display:grid;grid-template-columns:6px minmax(0,1fr);align-items:center;gap:7px;min-height:26px;padding:3px 7px;border:0;border-radius:7px;color:#738198;background:transparent;text-align:left;font-size:8px;cursor:pointer;transition:.18s ease}
.scroll-anchor-nav button i{width:4px;height:4px;border-radius:50%;background:#40506a;transition:.18s ease}
.scroll-anchor-nav button:hover,.scroll-anchor-nav button.active{color:#d7e5f9;background:rgba(57,125,246,.12)}
.scroll-anchor-nav button.active i{height:12px;border-radius:3px;background:#5794f7;box-shadow:0 0 10px rgba(87,148,247,.55)}
.scroll-anchor-nav button span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.anchor-nav-enter-active,.anchor-nav-leave-active{transition:opacity .2s ease,transform .2s ease}.anchor-nav-enter-from,.anchor-nav-leave-to{opacity:0;transform:translate(10px,-50%)}
@media(max-width:1180px){.scroll-anchor-nav{right:8px;max-width:38px}.scroll-anchor-nav button{grid-template-columns:6px;padding:3px 8px}.scroll-anchor-nav button span{display:none}}
@media(max-width:760px){.scroll-anchor-nav{display:none}}
</style>
