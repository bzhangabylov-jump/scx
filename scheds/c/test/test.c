/* Test program to verify shared memory communication with scx_firedancer */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

struct fd_scheduler_shm {
    int scheduler_pid;
    int test_counter;
    char message[256];
    struct {
        int pid;
        int registered;
        int idle;
        char name[64];
    } tiles[50];
};

int main(int argc, char **argv) {
    printf("Test program starting...\n");

    // Open existing shared memory (no O_CREAT)
    int shm_fd = shm_open("/fd_scheduler_shm", O_RDWR, 0666);
    if (shm_fd < 0) {
        printf("Failed to open shared memory: %s\n", strerror(errno));
        printf("Make sure scx_firedancer is running first!\n");
        return 1;
    }

    // Map the shared memory
    struct fd_scheduler_shm *shm = mmap(NULL, sizeof(struct fd_scheduler_shm),
                                       PROT_READ | PROT_WRITE, MAP_SHARED,
                                       shm_fd, 0);
    if (shm == MAP_FAILED) {
        printf("Failed to map shared memory: %s\n", strerror(errno));
        close(shm_fd);
        return 1;
    }

    close(shm_fd); // Can close after mmap

    printf("Successfully connected to shared memory!\n");
    printf("Scheduler PID: %d\n", shm->scheduler_pid);
    printf("Message from scheduler: '%s'\n", shm->message);
    printf("Current counter value: %d\n", shm->test_counter);

    // Register ourselves as a tile
    int my_tile_id = 0;
    if (argc > 1) {
        my_tile_id = atoi(argv[1]);
    }

    if (my_tile_id < 50) {
        shm->tiles[my_tile_id].pid = getpid();
        shm->tiles[my_tile_id].registered = 1;
        shm->tiles[my_tile_id].idle = 0;
        snprintf(shm->tiles[my_tile_id].name, 64, "test_tile_%d", my_tile_id);
        printf("Registered as tile %d\n", my_tile_id);
    }

    // Update the message
    snprintf(shm->message, 256, "Test program (PID %d) connected!", getpid());

    // Increment counter periodically to show activity
    for (int i = 0; i < 10; i++) {
        shm->test_counter++;
        printf("Counter updated to: %d\n", shm->test_counter);

        // Show active tiles
        printf("Registered tiles: ");
        for (int j = 0; j < 50; j++) {
            if (shm->tiles[j].registered) {
                printf("[%d:%s pid=%d idle=%d] ", j, shm->tiles[j].name, shm->tiles[j].pid, shm->tiles[j].idle);
            }
        }
        printf("\n");

        sleep(1);
    }

    // Mark ourselves as inactive before exit
    if (my_tile_id < 50) {
        shm->tiles[my_tile_id].registered = 0;
    }

    munmap(shm, sizeof(struct fd_scheduler_shm));
    printf("Test program finished\n");

    return 0;
}