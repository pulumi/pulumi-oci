// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.StackMonitoring.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.Integer;
import java.util.Objects;

@CustomType
public final class GetMonitoredResourceTaskTaskDetailReceiverProperty {
    /**
     * @return Receiver listener port.
     * 
     */
    private Integer listenerPort;

    private GetMonitoredResourceTaskTaskDetailReceiverProperty() {}
    /**
     * @return Receiver listener port.
     * 
     */
    public Integer listenerPort() {
        return this.listenerPort;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetMonitoredResourceTaskTaskDetailReceiverProperty defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private Integer listenerPort;
        public Builder() {}
        public Builder(GetMonitoredResourceTaskTaskDetailReceiverProperty defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.listenerPort = defaults.listenerPort;
        }

        @CustomType.Setter
        public Builder listenerPort(Integer listenerPort) {
            if (listenerPort == null) {
              throw new MissingRequiredPropertyException("GetMonitoredResourceTaskTaskDetailReceiverProperty", "listenerPort");
            }
            this.listenerPort = listenerPort;
            return this;
        }
        public GetMonitoredResourceTaskTaskDetailReceiverProperty build() {
            final var _resultValue = new GetMonitoredResourceTaskTaskDetailReceiverProperty();
            _resultValue.listenerPort = listenerPort;
            return _resultValue;
        }
    }
}
