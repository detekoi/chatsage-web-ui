document.addEventListener('DOMContentLoaded', () => {
    const canvas = document.getElementById('staticCanvas');
    // Important: Check if the canvas element actually exists before proceeding
    if (!canvas) {
        return;
    }
    const ctx = canvas.getContext('2d');

    let animationFrameId;
    // Use prefers-color-scheme to sync with your CSS :root variables
    let isDarkMode = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;

    // --- Configurable Parameters ---
    // Basic static effect configuration
    const config = {
        pixelSize: 1,       // Minimum pixel size for finest static
        density: 0.8,       // Base density for normal mode (increased to match default background)
        baseAlpha: 0.85,    // Base alpha for normal mode (increased slightly)
        alphaVariance: 0.25, // Alpha variance for normal mode

        // Color ranges (0-255) - Enhanced contrast
        darkIntensityMin: 30,  // Brighter dots on dark bg
        darkIntensityMax: 100, // Wider range for better visibility
        lightIntensityMin: 135, // Darker dots on light bg (increased contrast)
        lightIntensityMax: 200, // Wider range for better visibility
        
        // Frame timing
        frameInterval: 55, // Milliseconds between frames (~18fps) - Increased interval to reduce redraw frequency
        
        // Effect state tracking
        effectState: 'normal', // Can be 'normal', 'intensifying', 'intense', 'fading'
        
        // Intense mode parameters (what we transition to)
        intenseDensity: 1.5,    // Lowered density for intense mode to reduce load
        intenseColor: [200, 120, 255], // More vibrant purple magic color
        
        // Transition parameters
        transitionProgress: 0,   // Progress from 0-1
        transitionSpeed: 0.012,  // How much to increment per frame (lower = smoother)
        
        // Effect parameters that will be dynamically calculated
        currentDensity: 0.66,   // Will be updated during transitions
        currentColorMix: 0      // 0 = normal colors, 1 = intense colors
    };
    // -----------------------------

     let lastFrameTime = 0; // Needed only if using frameInterval

    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }

    function drawStatic(timestamp) { // timestamp is only needed if using frameInterval

        // --- Optional Frame Rate Limiting ---
        if (timestamp - lastFrameTime < config.frameInterval) {
            animationFrameId = requestAnimationFrame(drawStatic);
            return;
        }
        lastFrameTime = timestamp;
        // --------------------------------------

        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        // Update the effect state and transition progress
        updateEffectState();
        
        // APPROACH: Draw two layers of static
        // 1. Base layer - always present (regular static)
        // 2. Effect layer - varies with transitions (colored static)
        
        // BASE LAYER: Always draw the normal static first
        const baseStaticDots = Math.floor((canvas.width * canvas.height) / 50 * config.density);
        for (let i = 0; i < baseStaticDots; i++) {
            const x = Math.random() * canvas.width;
            const y = Math.random() * canvas.height;
            
            // Always use the normal static appearance for the base layer
            let intensity;
            if (isDarkMode) {
                intensity = config.darkIntensityMin + Math.random() * (config.darkIntensityMax - config.darkIntensityMin);
            } else {
                intensity = config.lightIntensityMin + Math.random() * (config.lightIntensityMax - config.lightIntensityMin);
            }
            intensity = Math.floor(intensity);
            
            const alpha = config.baseAlpha + (Math.random() - 0.5) * config.alphaVariance;
            
            ctx.fillStyle = `rgba(${intensity}, ${intensity}, ${intensity}, ${alpha})`;
            ctx.fillRect(x, y, config.pixelSize, config.pixelSize);
        }
        
        // EFFECT LAYER: Only if we're not in normal state
        if (config.effectState !== 'normal' && config.transitionProgress > 0) {
            // Calculate intensity dots - these have color and vary with transition
            // Adjust density based on dark mode - less intense in dark mode
            // Increased divisor to reduce number of effect dots
            const densityMultiplier = isDarkMode ? 50 : 40; // Higher divisor = fewer dots
            const effectDots = Math.floor((canvas.width * canvas.height) / densityMultiplier *
                (config.intenseDensity - config.density) * config.transitionProgress);

            // Draw dots with adjusted size for dark mode
            for (let i = 0; i < effectDots; i++) {
                const x = Math.random() * canvas.width;
                const y = Math.random() * canvas.height;
                
                // Get special effect color (purple/magic)
                const { r, g, b, alpha } = calculateEffectColor();
                
                // Smaller dots and fewer large ones in dark mode
                const largeThreshold = isDarkMode ? 0.95 : 0.9; // 5% large dots in dark mode vs 10% in light
                const dotSize = Math.random() > largeThreshold ? config.pixelSize * 2 : config.pixelSize;
                
                // Lower alpha for dark mode
                const effectiveAlpha = isDarkMode ? alpha * 0.8 : alpha;
                
                ctx.fillStyle = `rgba(${r}, ${g}, ${b}, ${effectiveAlpha})`;
                ctx.fillRect(x, y, dotSize, dotSize);
            }
            
            // Add some extra bright sparkles for additional visual impact - fewer in dark mode
            // Increased divisor significantly to reduce sparkle count
            const sparkleMultiplier = isDarkMode ? 4000 : 3000; // Higher divisor = fewer sparkles
            const sparkleCount = Math.floor((canvas.width * canvas.height) / sparkleMultiplier * config.transitionProgress);
            
            for (let i = 0; i < sparkleCount; i++) {
                const x = Math.random() * canvas.width;
                const y = Math.random() * canvas.height;
                
                // Lower opacity sparkles in dark mode
                const sparkleAlpha = isDarkMode ? 0.5 * config.transitionProgress : 0.7 * config.transitionProgress;
                
                // Always use white for these special sparkles
                ctx.fillStyle = `rgba(255, 255, 255, ${sparkleAlpha})`;
                ctx.fillRect(x, y, config.pixelSize * 2, config.pixelSize * 2);
            }
        }
        
        // Request the next frame
        animationFrameId = requestAnimationFrame(drawStatic);
    }
    
    // Helper function to update the effect state and transition progress
    function updateEffectState() {
        // Handle state transitions
        switch(config.effectState) {
            case 'intensifying':
                // Increase the transition progress
                config.transitionProgress += config.transitionSpeed;
                
                // If we've reached the maximum intensity
                if (config.transitionProgress >= 1) {
                    config.transitionProgress = 1;
                    config.effectState = 'intense'; // Switch to intense state
                }
                break;
                
            case 'fading':
                // Decrease the transition progress
                config.transitionProgress -= config.transitionSpeed;
                
                // If we've reached the normal state
                if (config.transitionProgress <= 0) {
                    config.transitionProgress = 0;
                    config.effectState = 'normal'; // Switch to normal state
                }
                break;
                
            // For 'normal' and 'intense' states, no progress updates needed
            // They are stable states representing the two extremes
        }
        
        // Update the current parameters based on transition progress
        updateCurrentParameters();
    }
    
    // Helper function to update current parameters based on transition progress
    function updateCurrentParameters() {
        // Interpolate between normal and intense parameters with easing
        // Use a quadratic easing function for smoother transitions at beginning and end
        const easeInOut = config.transitionProgress < 0.5 ? 
            2 * config.transitionProgress * config.transitionProgress : 
            1 - Math.pow(-2 * config.transitionProgress + 2, 2) / 2;
            
        // Set minimum density to never go below 90% of normal density
        // This ensures we never have a completely empty screen
        const minDensity = config.density * 0.9;
        
        // Calculate current density with easing and minimum
        config.currentDensity = Math.max(
            minDensity,
            config.density + (config.intenseDensity - config.density) * easeInOut
        );
            
        // Color mix can use the same easing for smooth transitions
        config.currentColorMix = easeInOut;
    }
    
    // Helper function to calculate the special effect color (used for magic/intense state)
    function calculateEffectColor() {
        // Calculate the intense color with some variation - adjust based on dark mode
        // Less vibrant colors in dark mode
        const colorIntensity = isDarkMode ? 0.85 : 1.0;
        
        // Apply dark mode adjustments to colors
        const intenseR = (config.intenseColor[0] * colorIntensity) + (Math.random() * 40 - 20);
        const intenseG = (config.intenseColor[1] * colorIntensity) + (Math.random() * 30 - 15);
        const intenseB = (config.intenseColor[2] * colorIntensity) + (Math.random() * 20 - 10);
        
        let r, g, b, alpha;
        
        // Add some colorful variation
        const colorRoll = Math.random();
        
        // White sparkles (less in dark mode)
        if (colorRoll > (isDarkMode ? 0.93 : 0.9)) { // 7% chance in dark mode vs 10% in light
            r = g = b = 255;
            // Dimmer white sparkles in dark mode
            alpha = Math.random() * (isDarkMode ? 0.7 : 0.95) * config.transitionProgress;
        }
        // Cyan accent sparkles (fewer in dark mode)
        else if (colorRoll > (isDarkMode ? 0.9 : 0.85)) { // 3% chance in dark mode vs 5% in light
            r = 100 + Math.random() * 50;
            g = 220 + Math.random() * 35;
            b = 255;
            // Dimmer cyan sparkles in dark mode
            alpha = ((isDarkMode ? 0.6 : 0.8) + Math.random() * 0.2) * config.transitionProgress;
        }
        // Main purple/magic color
        else {
            // Use the intense colors with adjusted alpha based on mode
            r = intenseR;
            g = intenseG;
            b = intenseB;
            // Lower alpha for dark mode
            const baseAlpha = isDarkMode ? 0.75 : 0.9;
            alpha = (baseAlpha + (Math.random() * 0.1 - 0.05)) * config.transitionProgress;
        }
        
        // Ensure values are in valid range
        r = Math.min(255, Math.max(0, Math.floor(r)));
        g = Math.min(255, Math.max(0, Math.floor(g)));
        b = Math.min(255, Math.max(0, Math.floor(b)));
        
        return { r, g, b, alpha };
    }

    // Function to update the mode based on the media query
    function updateMode(event) {
        isDarkMode = event.matches;
        // Optionally redraw immediately or wait for the next animation frame
        // requestAnimationFrame(drawStatic); // Uncomment for immediate redraw on theme change
    }
    
    // Keep track of automatic state changes
    let autoChangeTimeout = null;
    
    // Function to trigger the intensifying effect (NEUTRALIZED FOR BACKGROUND)
    function enableMagicMode() {
        // console.log("Background magic mode trigger received, but effect is disabled.");
        // Keep the background in the normal state
        config.effectState = 'normal';
        config.transitionProgress = 0;
    }
    
    // Function to trigger the fading effect (ENSURES BACKGROUND IS NORMAL)
    function disableMagicMode() {
        // console.log("Background magic mode disable trigger received.");
        // Always ensure the background returns to/stays in the normal state
        config.effectState = 'normal';
        config.transitionProgress = 0;
    }

    // Initial Setup
    resizeCanvas(); // Set initial size

    // Event Listeners
    window.addEventListener('resize', resizeCanvas);

    // Initialize system to normal state
    config.effectState = 'normal';
    config.transitionProgress = 0;
    
    // Initialize current parameters (density, etc.)
    updateCurrentParameters();
    
    // Start the animation
    animationFrameId = requestAnimationFrame(drawStatic);
    
    // Expose functions to window for other scripts to use
    window.staticBackground = {
        enableMagicMode,    // Transition to intense state
        disableMagicMode,   // Transition back to normal state
        
        // Add some utility functions for direct state control if needed
        setIntense: function() {
            config.effectState = 'intense';
            config.transitionProgress = 1;
            updateCurrentParameters();
        },
        setNormal: function() {
            config.effectState = 'normal';
            config.transitionProgress = 0;
            updateCurrentParameters();
        }
    };

    // Listen for system theme changes
    const darkModeMediaQuery = window.matchMedia('(prefers-color-scheme: dark)');
    darkModeMediaQuery.addEventListener('change', updateMode);
     // Initialize isDarkMode based on current state
    isDarkMode = darkModeMediaQuery.matches;


    // Optional: Stop animation when tab is not visible (performance)
    document.addEventListener('visibilitychange', () => {
        if (document.hidden) {
            cancelAnimationFrame(animationFrameId);
        } else {
            // Restart the animation loop
            animationFrameId = requestAnimationFrame(drawStatic);
        }
    });
    
    // Note: Magic mode is now explicitly controlled by gemini-mascot.js
    // so we've removed the automatic observer to avoid conflicts

}); // End DOMContentLoaded
