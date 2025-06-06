// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Desktops.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.lang.String;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class DesktopPoolSessionLifecycleActionsInactivity {
    /**
     * @return (Updatable) an inactivity action to be triggered. Could be set to NONE or DISCONNECT.
     * 
     */
    private String action;
    /**
     * @return (Updatable) The period of time (in minutes) during which the session must remain inactive before any action occurs. If the value is not provided, a default value is used.
     * 
     */
    private @Nullable Integer gracePeriodInMinutes;

    private DesktopPoolSessionLifecycleActionsInactivity() {}
    /**
     * @return (Updatable) an inactivity action to be triggered. Could be set to NONE or DISCONNECT.
     * 
     */
    public String action() {
        return this.action;
    }
    /**
     * @return (Updatable) The period of time (in minutes) during which the session must remain inactive before any action occurs. If the value is not provided, a default value is used.
     * 
     */
    public Optional<Integer> gracePeriodInMinutes() {
        return Optional.ofNullable(this.gracePeriodInMinutes);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(DesktopPoolSessionLifecycleActionsInactivity defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String action;
        private @Nullable Integer gracePeriodInMinutes;
        public Builder() {}
        public Builder(DesktopPoolSessionLifecycleActionsInactivity defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.action = defaults.action;
    	      this.gracePeriodInMinutes = defaults.gracePeriodInMinutes;
        }

        @CustomType.Setter
        public Builder action(String action) {
            if (action == null) {
              throw new MissingRequiredPropertyException("DesktopPoolSessionLifecycleActionsInactivity", "action");
            }
            this.action = action;
            return this;
        }
        @CustomType.Setter
        public Builder gracePeriodInMinutes(@Nullable Integer gracePeriodInMinutes) {

            this.gracePeriodInMinutes = gracePeriodInMinutes;
            return this;
        }
        public DesktopPoolSessionLifecycleActionsInactivity build() {
            final var _resultValue = new DesktopPoolSessionLifecycleActionsInactivity();
            _resultValue.action = action;
            _resultValue.gracePeriodInMinutes = gracePeriodInMinutes;
            return _resultValue;
        }
    }
}
