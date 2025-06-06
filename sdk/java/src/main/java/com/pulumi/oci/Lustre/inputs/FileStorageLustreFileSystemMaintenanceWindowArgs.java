// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Lustre.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class FileStorageLustreFileSystemMaintenanceWindowArgs extends com.pulumi.resources.ResourceArgs {

    public static final FileStorageLustreFileSystemMaintenanceWindowArgs Empty = new FileStorageLustreFileSystemMaintenanceWindowArgs();

    /**
     * Day of the week when the maintainence window starts.
     * 
     */
    @Import(name="dayOfWeek")
    private @Nullable Output<String> dayOfWeek;

    /**
     * @return Day of the week when the maintainence window starts.
     * 
     */
    public Optional<Output<String>> dayOfWeek() {
        return Optional.ofNullable(this.dayOfWeek);
    }

    /**
     * The time to start the maintenance window. The format is &#39;HH:MM&#39;, &#39;HH:MM&#39; represents the time in UTC.   Example: `22:00`
     * 
     */
    @Import(name="timeStart")
    private @Nullable Output<String> timeStart;

    /**
     * @return The time to start the maintenance window. The format is &#39;HH:MM&#39;, &#39;HH:MM&#39; represents the time in UTC.   Example: `22:00`
     * 
     */
    public Optional<Output<String>> timeStart() {
        return Optional.ofNullable(this.timeStart);
    }

    private FileStorageLustreFileSystemMaintenanceWindowArgs() {}

    private FileStorageLustreFileSystemMaintenanceWindowArgs(FileStorageLustreFileSystemMaintenanceWindowArgs $) {
        this.dayOfWeek = $.dayOfWeek;
        this.timeStart = $.timeStart;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(FileStorageLustreFileSystemMaintenanceWindowArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private FileStorageLustreFileSystemMaintenanceWindowArgs $;

        public Builder() {
            $ = new FileStorageLustreFileSystemMaintenanceWindowArgs();
        }

        public Builder(FileStorageLustreFileSystemMaintenanceWindowArgs defaults) {
            $ = new FileStorageLustreFileSystemMaintenanceWindowArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param dayOfWeek Day of the week when the maintainence window starts.
         * 
         * @return builder
         * 
         */
        public Builder dayOfWeek(@Nullable Output<String> dayOfWeek) {
            $.dayOfWeek = dayOfWeek;
            return this;
        }

        /**
         * @param dayOfWeek Day of the week when the maintainence window starts.
         * 
         * @return builder
         * 
         */
        public Builder dayOfWeek(String dayOfWeek) {
            return dayOfWeek(Output.of(dayOfWeek));
        }

        /**
         * @param timeStart The time to start the maintenance window. The format is &#39;HH:MM&#39;, &#39;HH:MM&#39; represents the time in UTC.   Example: `22:00`
         * 
         * @return builder
         * 
         */
        public Builder timeStart(@Nullable Output<String> timeStart) {
            $.timeStart = timeStart;
            return this;
        }

        /**
         * @param timeStart The time to start the maintenance window. The format is &#39;HH:MM&#39;, &#39;HH:MM&#39; represents the time in UTC.   Example: `22:00`
         * 
         * @return builder
         * 
         */
        public Builder timeStart(String timeStart) {
            return timeStart(Output.of(timeStart));
        }

        public FileStorageLustreFileSystemMaintenanceWindowArgs build() {
            return $;
        }
    }

}
