import matplotlib.pyplot as plt
import numpy as np
from mpl_toolkits.mplot3d import Axes3D
import mpl_toolkits.mplot3d.art3d as art3d

def draw_wall_pickleball_court_3d():
    # Dimensions in feet
    WIDTH_FT = 136 / 12  # ≈11.333 ft
    DEPTH = 16.0         # 16 feet deep
    KITCHEN_DEPTH = 7.0  # Kitchen line 7 ft from wall
    WIDTH = WIDTH_FT
    
    fig = plt.figure(figsize=(12, 9))
    ax = fig.add_subplot(111, projection='3d')
    
    # Floor - white
    verts = [(0, 0, 0), (WIDTH, 0, 0), (WIDTH, DEPTH, 0), (0, DEPTH, 0)]
    floor = art3d.Poly3DCollection([verts], facecolor='white', alpha=1.0, edgecolor='none')
    ax.add_collection3d(floor)
    
    # Back wall - white
    wall_verts = [(0, 0, 0), (WIDTH, 0, 0), (WIDTH, 0, 4), (0, 0, 4)]
    wall = art3d.Poly3DCollection([wall_verts], facecolor='white', alpha=1.0, edgecolor='none')
    ax.add_collection3d(wall)
    
    # Helper for floor lines
    def plot_floor_line(x1, x2, y1, y2, color='red', lw=4):
        ax.plot([x1, x2], [y1, y2], [0, 0], color=color, linewidth=lw)
    
    # Side lines
    plot_floor_line(0, 0, 0, DEPTH, lw=6)
    plot_floor_line(WIDTH, WIDTH, 0, DEPTH, lw=6)
    
    # Back line at 16 ft
    plot_floor_line(0, WIDTH, DEPTH, DEPTH, lw=6)
    
    # Kitchen line - extra thick and bright red as requested
    plot_floor_line(0, WIDTH, KITCHEN_DEPTH, KITCHEN_DEPTH, color='red', lw=10)
    
    # Center line
    mid_x = WIDTH / 2
    plot_floor_line(mid_x, mid_x, 0, DEPTH, lw=5)
    
    # Net on the wall
    NET_HEIGHT_SIDES = 3.0      # 36 inches = 3 ft
    NET_HEIGHT_CENTER = 34 / 12 # ≈2.833 ft
    
    # Posts
    ax.plot([0, 0], [0, 0], [0, NET_HEIGHT_SIDES], color='red', lw=6)
    ax.plot([WIDTH, WIDTH], [0, 0], [0, NET_HEIGHT_SIDES], color='red', lw=6)
    
    # Top of net with sag - already red and thick
    x_net = np.linspace(0, WIDTH, 100)
    sag = (NET_HEIGHT_SIDES - NET_HEIGHT_CENTER) * np.sin(np.pi * x_net / WIDTH)**2
    z_net = NET_HEIGHT_SIDES - sag
    ax.plot(x_net, np.zeros(100), z_net, color='red', lw=10)  # Extra thick top line
    
    # Net mesh - lighter red vertical strands
    for x in np.linspace(0, WIDTH, 25):
        sag_here = (NET_HEIGHT_SIDES - NET_HEIGHT_CENTER) * np.sin(np.pi * x / WIDTH)**2
        height_here = NET_HEIGHT_SIDES - sag_here
        ax.plot([x, x], [0, 0], [0, height_here], color='red', lw=2, alpha=0.8)
    
    # Labels
    ax.set_xlabel('Width (feet)')
    ax.set_ylabel('Depth from Wall (feet)')
    ax.set_zlabel('Height (feet)')
    ax.set_title('Wall-Mounted Pickleball Practice Court\nKitchen Line & Net Top Line Extra Bright/Thick Red')
    
    ax.set_xlim(0, WIDTH)
    ax.set_ylim(0, DEPTH)
    ax.set_zlim(0, 4)
    
    ax.view_init(elev=30, azim=-70)
    ax.grid(False)
    ax.axis('off')  # Clean view
    
    plt.show()

# Run the function
draw_wall_pickleball_court_3d()