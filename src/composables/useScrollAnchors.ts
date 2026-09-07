import { nextTick, onBeforeUnmount, onMounted, ref, watch, type Ref } from 'vue'

export interface ScrollAnchor {
  id: string
  label: string
}

export function useScrollAnchors(anchors: Ref<ScrollAnchor[]>, revealAfter = 420) {
  const visible = ref(false)
  const activeId = ref('')
  let observer: IntersectionObserver | undefined
  let frame = 0

  function updateVisibility() {
    cancelAnimationFrame(frame)
    frame = requestAnimationFrame(() => {
      visible.value = window.scrollY >= revealAfter && anchors.value.length > 1
    })
  }

  async function observeAnchors() {
    await nextTick()
    observer?.disconnect()
    observer = new IntersectionObserver((entries) => {
      const visibleEntries = entries
        .filter((entry) => entry.isIntersecting)
        .sort((left, right) => left.boundingClientRect.top - right.boundingClientRect.top)
      if (visibleEntries[0]?.target.id) activeId.value = visibleEntries[0].target.id
    }, { rootMargin: '-18% 0px -68% 0px', threshold: [0, 0.01] })
    for (const anchor of anchors.value) {
      const element = document.getElementById(anchor.id)
      if (element) observer.observe(element)
    }
    if (!activeId.value || !anchors.value.some((anchor) => anchor.id === activeId.value)) {
      activeId.value = anchors.value.find((anchor) => document.getElementById(anchor.id))?.id || ''
    }
    updateVisibility()
  }

  async function scrollToAnchor(id: string) {
    await nextTick()
    const element = document.getElementById(id)
    if (element && observer) observer.observe(element)
    element?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    activeId.value = id
  }

  watch(anchors, observeAnchors, { deep: true, flush: 'post' })
  onMounted(() => {
    window.addEventListener('scroll', updateVisibility, { passive: true })
    void observeAnchors()
  })
  onBeforeUnmount(() => {
    window.removeEventListener('scroll', updateVisibility)
    cancelAnimationFrame(frame)
    observer?.disconnect()
  })

  return { visible, activeId, observeAnchors, scrollToAnchor }
}
