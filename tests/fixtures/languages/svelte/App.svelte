<script>
    import { onMount } from 'svelte';
    import Header from './Header.svelte';
    import Footer from './Footer.svelte';
    import { api } from './lib/api.js';

    let name = 'world';
    let count = 0;

    onMount(() => {
        api.fetch('/data').then(res => {
            count = res.length;
        });
    });

    function handleClick() {
        count += 1;
        name = `clicked ${count} times`;
    }
</script>

<Header title="Svelte App" />
<main>
    <h1>Hello {name}!</h1>
    <button on:click={handleClick}>
        Click me
    </button>
</main>
<Footer year={2026} />

<style>
    h1 {
        color: #ff3e00;
        font-size: 2rem;
    }
    main {
        text-align: center;
        padding: 2rem;
    }
</style>
