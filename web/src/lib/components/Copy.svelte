<script lang="ts">
import { Check, Copy } from "phosphor-svelte";
import { copyToClipboard } from "$lib/clipboard";

let {
    value,
    size = "20",
    showText = false,
    extraClasses,
}: {
    value: string;
    size?: string;
    showText?: boolean;
    extraClasses?: string;
} = $props();

let copySuccess = $state(false);

async function copyListId() {
    try {
        await copyToClipboard(value);
        copySuccess = true;
        setTimeout(() => {
            copySuccess = false;
        }, 1500);
    } catch (err) {
        console.error("Failed to copy: ", err);
    }
}
</script>
    
    <button onclick={copyListId} class="border-none outline-hidden ring-none {extraClasses}">
        {#if copySuccess}
            <Check weight="light" {size} class="text-green-500" />
        {:else}
            <Copy weight="light" {size} />
        {/if}
        {#if showText}
            Copy ID
        {/if}
    </button>
    