package dev.beenary.util;

public class Defense {

    public static <T> void notNull(T value, String name){
        if(value == null){
            throw new IllegalArgumentException(String.format("Parameter %s cannot be null.", name));
        }
    }
}
