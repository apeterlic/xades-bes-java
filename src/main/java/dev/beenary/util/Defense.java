package dev.beenary.util;

/**
 * Contains common methods.
 *
 * @author Ana Peterlić
 */
public class Defense {

    public static <T> void notNull(final T value, final String name) {
        if (value == null) {
            throw new IllegalArgumentException(String.format("Parameter %s cannot be null.", name));
        }
    }

    /**
     * Class contains only static members and should never be instantiated.
     */
    private Defense() {
    }
}
