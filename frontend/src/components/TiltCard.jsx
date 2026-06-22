import { useState, useEffect, useRef } from 'react';
import { motion, useSpring, useTransform } from 'framer-motion';

export default function TiltCard({ children, className = '', ...props }) {
  const ref = useRef(null);
  
  // Mouse position relative to center of card
  const x = useSpring(0, { stiffness: 300, damping: 30 });
  const y = useSpring(0, { stiffness: 300, damping: 30 });

  // Transform coordinates to rotation
  const rotateX = useTransform(y, [-0.5, 0.5], [2, -2]);
  const rotateY = useTransform(x, [-0.5, 0.5], [-2, 2]);

  const handleMouseMove = (e) => {
    if (!ref.current) return;
    const rect = ref.current.getBoundingClientRect();
    
    // Calculate position from -0.5 to +0.5
    const width = rect.width;
    const height = rect.height;
    
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;
    
    const xPct = (mouseX / width) - 0.5;
    const yPct = (mouseY / height) - 0.5;
    
    x.set(xPct);
    y.set(yPct);
  };

  const handleMouseLeave = () => {
    x.set(0);
    y.set(0);
  };

  return (
    <motion.div
      ref={ref}
      className={`glass-panel ${className}`}
      onMouseMove={handleMouseMove}
      onMouseLeave={handleMouseLeave}
      style={{
        rotateX,
        rotateY,
        transformPerspective: 800,
        ...props.style
      }}
      whileHover={{ scale: 1.01, zIndex: 10 }}
      transition={{ duration: 0.2 }}
      {...props}
    >
      {children}
    </motion.div>
  );
}
