// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Lustre.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetFileStorageLustreFileSystemMaintenanceWindow {
    /**
     * @return Day of the week when the maintainence window starts.
     * 
     */
    private String dayOfWeek;
    /**
     * @return The time to start the maintenance window. The format is &#39;HH:MM&#39;, &#39;HH:MM&#39; represents the time in UTC.   Example: `22:00`
     * 
     */
    private String timeStart;

    private GetFileStorageLustreFileSystemMaintenanceWindow() {}
    /**
     * @return Day of the week when the maintainence window starts.
     * 
     */
    public String dayOfWeek() {
        return this.dayOfWeek;
    }
    /**
     * @return The time to start the maintenance window. The format is &#39;HH:MM&#39;, &#39;HH:MM&#39; represents the time in UTC.   Example: `22:00`
     * 
     */
    public String timeStart() {
        return this.timeStart;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFileStorageLustreFileSystemMaintenanceWindow defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String dayOfWeek;
        private String timeStart;
        public Builder() {}
        public Builder(GetFileStorageLustreFileSystemMaintenanceWindow defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.dayOfWeek = defaults.dayOfWeek;
    	      this.timeStart = defaults.timeStart;
        }

        @CustomType.Setter
        public Builder dayOfWeek(String dayOfWeek) {
            if (dayOfWeek == null) {
              throw new MissingRequiredPropertyException("GetFileStorageLustreFileSystemMaintenanceWindow", "dayOfWeek");
            }
            this.dayOfWeek = dayOfWeek;
            return this;
        }
        @CustomType.Setter
        public Builder timeStart(String timeStart) {
            if (timeStart == null) {
              throw new MissingRequiredPropertyException("GetFileStorageLustreFileSystemMaintenanceWindow", "timeStart");
            }
            this.timeStart = timeStart;
            return this;
        }
        public GetFileStorageLustreFileSystemMaintenanceWindow build() {
            final var _resultValue = new GetFileStorageLustreFileSystemMaintenanceWindow();
            _resultValue.dayOfWeek = dayOfWeek;
            _resultValue.timeStart = timeStart;
            return _resultValue;
        }
    }
}
