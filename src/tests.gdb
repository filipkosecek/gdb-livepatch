#test trampoline
define test-trampoline
    set $i = 0
    while $i < 13
        p/x $TRAMPOLINE[$i]
        set $i += 1
    end

#test target function
define test-target-function
    set $i = 0
    while $i < 18
        p/x $TARGET_ADDR[$i]
        set $i += 1
    end

#test patch object
define test-patch-object
    set $i = 0
    while $i < 29
        p/x $PATCH_ADDR[$i]
        set $i += 1
    end

#overall test
define test-all
    set $i = 0
    while $i <= 19
        p/x x
        next
        set $i += 1
    end
