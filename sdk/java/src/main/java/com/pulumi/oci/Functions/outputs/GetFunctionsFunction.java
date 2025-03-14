// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Functions.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Functions.outputs.GetFunctionsFunctionProvisionedConcurrencyConfig;
import com.pulumi.oci.Functions.outputs.GetFunctionsFunctionSourceDetail;
import com.pulumi.oci.Functions.outputs.GetFunctionsFunctionTraceConfig;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@CustomType
public final class GetFunctionsFunction {
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the application to which this function belongs.
     * 
     */
    private String applicationId;
    /**
     * @return The OCID of the compartment that contains the function.
     * 
     */
    private String compartmentId;
    /**
     * @return Function configuration. Overrides application configuration. Keys must be ASCII strings consisting solely of letters, digits, and the &#39;_&#39; (underscore) character, and must not begin with a digit. Values should be limited to printable unicode characters.  Example: `{&#34;MY_FUNCTION_CONFIG&#34;: &#34;ConfVal&#34;}`
     * 
     */
    private Map<String,String> config;
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    private Map<String,String> definedTags;
    /**
     * @return A filter to return only functions with display names that match the display name string. Matching is exact.
     * 
     */
    private String displayName;
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    private Map<String,String> freeformTags;
    /**
     * @return A filter to return only functions with the specified OCID.
     * 
     */
    private String id;
    /**
     * @return The qualified name of the Docker image to use in the function, including the image tag. The image should be in the Oracle Cloud Infrastructure Registry that is in the same region as the function itself. Example: `phx.ocir.io/ten/functions/function:0.0.1`
     * 
     */
    private String image;
    /**
     * @return The image digest for the version of the image that will be pulled when invoking this function. If no value is specified, the digest currently associated with the image in the Oracle Cloud Infrastructure Registry will be used. Example: `sha256:ca0eeb6fb05351dfc8759c20733c91def84cb8007aa89a5bf606bc8b315b9fc7`
     * 
     */
    private String imageDigest;
    /**
     * @return The base https invoke URL to set on a client in order to invoke a function. This URL will never change over the lifetime of the function and can be cached.
     * 
     */
    private String invokeEndpoint;
    /**
     * @return Maximum usable memory for the function (MiB).
     * 
     */
    private String memoryInMbs;
    /**
     * @return Define the strategy for provisioned concurrency for the function.
     * 
     */
    private List<GetFunctionsFunctionProvisionedConcurrencyConfig> provisionedConcurrencyConfigs;
    /**
     * @return The processor shape (`GENERIC_X86`/`GENERIC_ARM`) on which to run functions in the application, extracted from the image manifest.
     * 
     */
    private String shape;
    /**
     * @return The source details for the Function. The function can be created from various sources.
     * 
     */
    private List<GetFunctionsFunctionSourceDetail> sourceDetails;
    /**
     * @return A filter to return only functions that match the lifecycle state in this parameter. Example: `Creating`
     * 
     */
    private String state;
    /**
     * @return The time the function was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     * 
     */
    private String timeCreated;
    /**
     * @return The time the function was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     * 
     */
    private String timeUpdated;
    /**
     * @return Timeout for executions of the function. Value in seconds.
     * 
     */
    private Integer timeoutInSeconds;
    /**
     * @return Define the tracing configuration for a function.
     * 
     */
    private List<GetFunctionsFunctionTraceConfig> traceConfigs;

    private GetFunctionsFunction() {}
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the application to which this function belongs.
     * 
     */
    public String applicationId() {
        return this.applicationId;
    }
    /**
     * @return The OCID of the compartment that contains the function.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return Function configuration. Overrides application configuration. Keys must be ASCII strings consisting solely of letters, digits, and the &#39;_&#39; (underscore) character, and must not begin with a digit. Values should be limited to printable unicode characters.  Example: `{&#34;MY_FUNCTION_CONFIG&#34;: &#34;ConfVal&#34;}`
     * 
     */
    public Map<String,String> config() {
        return this.config;
    }
    /**
     * @return Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Map<String,String> definedTags() {
        return this.definedTags;
    }
    /**
     * @return A filter to return only functions with display names that match the display name string. Matching is exact.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    /**
     * @return Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Map<String,String> freeformTags() {
        return this.freeformTags;
    }
    /**
     * @return A filter to return only functions with the specified OCID.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The qualified name of the Docker image to use in the function, including the image tag. The image should be in the Oracle Cloud Infrastructure Registry that is in the same region as the function itself. Example: `phx.ocir.io/ten/functions/function:0.0.1`
     * 
     */
    public String image() {
        return this.image;
    }
    /**
     * @return The image digest for the version of the image that will be pulled when invoking this function. If no value is specified, the digest currently associated with the image in the Oracle Cloud Infrastructure Registry will be used. Example: `sha256:ca0eeb6fb05351dfc8759c20733c91def84cb8007aa89a5bf606bc8b315b9fc7`
     * 
     */
    public String imageDigest() {
        return this.imageDigest;
    }
    /**
     * @return The base https invoke URL to set on a client in order to invoke a function. This URL will never change over the lifetime of the function and can be cached.
     * 
     */
    public String invokeEndpoint() {
        return this.invokeEndpoint;
    }
    /**
     * @return Maximum usable memory for the function (MiB).
     * 
     */
    public String memoryInMbs() {
        return this.memoryInMbs;
    }
    /**
     * @return Define the strategy for provisioned concurrency for the function.
     * 
     */
    public List<GetFunctionsFunctionProvisionedConcurrencyConfig> provisionedConcurrencyConfigs() {
        return this.provisionedConcurrencyConfigs;
    }
    /**
     * @return The processor shape (`GENERIC_X86`/`GENERIC_ARM`) on which to run functions in the application, extracted from the image manifest.
     * 
     */
    public String shape() {
        return this.shape;
    }
    /**
     * @return The source details for the Function. The function can be created from various sources.
     * 
     */
    public List<GetFunctionsFunctionSourceDetail> sourceDetails() {
        return this.sourceDetails;
    }
    /**
     * @return A filter to return only functions that match the lifecycle state in this parameter. Example: `Creating`
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The time the function was created, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return The time the function was updated, expressed in [RFC 3339](https://tools.ietf.org/html/rfc3339) timestamp format.  Example: `2018-09-12T22:47:12.613Z`
     * 
     */
    public String timeUpdated() {
        return this.timeUpdated;
    }
    /**
     * @return Timeout for executions of the function. Value in seconds.
     * 
     */
    public Integer timeoutInSeconds() {
        return this.timeoutInSeconds;
    }
    /**
     * @return Define the tracing configuration for a function.
     * 
     */
    public List<GetFunctionsFunctionTraceConfig> traceConfigs() {
        return this.traceConfigs;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetFunctionsFunction defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String applicationId;
        private String compartmentId;
        private Map<String,String> config;
        private Map<String,String> definedTags;
        private String displayName;
        private Map<String,String> freeformTags;
        private String id;
        private String image;
        private String imageDigest;
        private String invokeEndpoint;
        private String memoryInMbs;
        private List<GetFunctionsFunctionProvisionedConcurrencyConfig> provisionedConcurrencyConfigs;
        private String shape;
        private List<GetFunctionsFunctionSourceDetail> sourceDetails;
        private String state;
        private String timeCreated;
        private String timeUpdated;
        private Integer timeoutInSeconds;
        private List<GetFunctionsFunctionTraceConfig> traceConfigs;
        public Builder() {}
        public Builder(GetFunctionsFunction defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.applicationId = defaults.applicationId;
    	      this.compartmentId = defaults.compartmentId;
    	      this.config = defaults.config;
    	      this.definedTags = defaults.definedTags;
    	      this.displayName = defaults.displayName;
    	      this.freeformTags = defaults.freeformTags;
    	      this.id = defaults.id;
    	      this.image = defaults.image;
    	      this.imageDigest = defaults.imageDigest;
    	      this.invokeEndpoint = defaults.invokeEndpoint;
    	      this.memoryInMbs = defaults.memoryInMbs;
    	      this.provisionedConcurrencyConfigs = defaults.provisionedConcurrencyConfigs;
    	      this.shape = defaults.shape;
    	      this.sourceDetails = defaults.sourceDetails;
    	      this.state = defaults.state;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeUpdated = defaults.timeUpdated;
    	      this.timeoutInSeconds = defaults.timeoutInSeconds;
    	      this.traceConfigs = defaults.traceConfigs;
        }

        @CustomType.Setter
        public Builder applicationId(String applicationId) {
            if (applicationId == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "applicationId");
            }
            this.applicationId = applicationId;
            return this;
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder config(Map<String,String> config) {
            if (config == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "config");
            }
            this.config = config;
            return this;
        }
        @CustomType.Setter
        public Builder definedTags(Map<String,String> definedTags) {
            if (definedTags == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "definedTags");
            }
            this.definedTags = definedTags;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder freeformTags(Map<String,String> freeformTags) {
            if (freeformTags == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "freeformTags");
            }
            this.freeformTags = freeformTags;
            return this;
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder image(String image) {
            if (image == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "image");
            }
            this.image = image;
            return this;
        }
        @CustomType.Setter
        public Builder imageDigest(String imageDigest) {
            if (imageDigest == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "imageDigest");
            }
            this.imageDigest = imageDigest;
            return this;
        }
        @CustomType.Setter
        public Builder invokeEndpoint(String invokeEndpoint) {
            if (invokeEndpoint == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "invokeEndpoint");
            }
            this.invokeEndpoint = invokeEndpoint;
            return this;
        }
        @CustomType.Setter
        public Builder memoryInMbs(String memoryInMbs) {
            if (memoryInMbs == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "memoryInMbs");
            }
            this.memoryInMbs = memoryInMbs;
            return this;
        }
        @CustomType.Setter
        public Builder provisionedConcurrencyConfigs(List<GetFunctionsFunctionProvisionedConcurrencyConfig> provisionedConcurrencyConfigs) {
            if (provisionedConcurrencyConfigs == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "provisionedConcurrencyConfigs");
            }
            this.provisionedConcurrencyConfigs = provisionedConcurrencyConfigs;
            return this;
        }
        public Builder provisionedConcurrencyConfigs(GetFunctionsFunctionProvisionedConcurrencyConfig... provisionedConcurrencyConfigs) {
            return provisionedConcurrencyConfigs(List.of(provisionedConcurrencyConfigs));
        }
        @CustomType.Setter
        public Builder shape(String shape) {
            if (shape == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "shape");
            }
            this.shape = shape;
            return this;
        }
        @CustomType.Setter
        public Builder sourceDetails(List<GetFunctionsFunctionSourceDetail> sourceDetails) {
            if (sourceDetails == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "sourceDetails");
            }
            this.sourceDetails = sourceDetails;
            return this;
        }
        public Builder sourceDetails(GetFunctionsFunctionSourceDetail... sourceDetails) {
            return sourceDetails(List.of(sourceDetails));
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeUpdated(String timeUpdated) {
            if (timeUpdated == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "timeUpdated");
            }
            this.timeUpdated = timeUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder timeoutInSeconds(Integer timeoutInSeconds) {
            if (timeoutInSeconds == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "timeoutInSeconds");
            }
            this.timeoutInSeconds = timeoutInSeconds;
            return this;
        }
        @CustomType.Setter
        public Builder traceConfigs(List<GetFunctionsFunctionTraceConfig> traceConfigs) {
            if (traceConfigs == null) {
              throw new MissingRequiredPropertyException("GetFunctionsFunction", "traceConfigs");
            }
            this.traceConfigs = traceConfigs;
            return this;
        }
        public Builder traceConfigs(GetFunctionsFunctionTraceConfig... traceConfigs) {
            return traceConfigs(List.of(traceConfigs));
        }
        public GetFunctionsFunction build() {
            final var _resultValue = new GetFunctionsFunction();
            _resultValue.applicationId = applicationId;
            _resultValue.compartmentId = compartmentId;
            _resultValue.config = config;
            _resultValue.definedTags = definedTags;
            _resultValue.displayName = displayName;
            _resultValue.freeformTags = freeformTags;
            _resultValue.id = id;
            _resultValue.image = image;
            _resultValue.imageDigest = imageDigest;
            _resultValue.invokeEndpoint = invokeEndpoint;
            _resultValue.memoryInMbs = memoryInMbs;
            _resultValue.provisionedConcurrencyConfigs = provisionedConcurrencyConfigs;
            _resultValue.shape = shape;
            _resultValue.sourceDetails = sourceDetails;
            _resultValue.state = state;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeUpdated = timeUpdated;
            _resultValue.timeoutInSeconds = timeoutInSeconds;
            _resultValue.traceConfigs = traceConfigs;
            return _resultValue;
        }
    }
}
