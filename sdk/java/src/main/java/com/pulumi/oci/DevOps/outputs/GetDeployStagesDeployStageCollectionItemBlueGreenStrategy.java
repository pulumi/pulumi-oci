// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DevOps.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetDeployStagesDeployStageCollectionItemBlueGreenStrategy {
    /**
     * @return Name of the Ingress resource.
     * 
     */
    private String ingressName;
    /**
     * @return First Namespace for deployment.
     * 
     */
    private String namespaceA;
    /**
     * @return Second Namespace for deployment.
     * 
     */
    private String namespaceB;
    /**
     * @return Canary strategy type.
     * 
     */
    private String strategyType;

    private GetDeployStagesDeployStageCollectionItemBlueGreenStrategy() {}
    /**
     * @return Name of the Ingress resource.
     * 
     */
    public String ingressName() {
        return this.ingressName;
    }
    /**
     * @return First Namespace for deployment.
     * 
     */
    public String namespaceA() {
        return this.namespaceA;
    }
    /**
     * @return Second Namespace for deployment.
     * 
     */
    public String namespaceB() {
        return this.namespaceB;
    }
    /**
     * @return Canary strategy type.
     * 
     */
    public String strategyType() {
        return this.strategyType;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetDeployStagesDeployStageCollectionItemBlueGreenStrategy defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String ingressName;
        private String namespaceA;
        private String namespaceB;
        private String strategyType;
        public Builder() {}
        public Builder(GetDeployStagesDeployStageCollectionItemBlueGreenStrategy defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.ingressName = defaults.ingressName;
    	      this.namespaceA = defaults.namespaceA;
    	      this.namespaceB = defaults.namespaceB;
    	      this.strategyType = defaults.strategyType;
        }

        @CustomType.Setter
        public Builder ingressName(String ingressName) {
            if (ingressName == null) {
              throw new MissingRequiredPropertyException("GetDeployStagesDeployStageCollectionItemBlueGreenStrategy", "ingressName");
            }
            this.ingressName = ingressName;
            return this;
        }
        @CustomType.Setter
        public Builder namespaceA(String namespaceA) {
            if (namespaceA == null) {
              throw new MissingRequiredPropertyException("GetDeployStagesDeployStageCollectionItemBlueGreenStrategy", "namespaceA");
            }
            this.namespaceA = namespaceA;
            return this;
        }
        @CustomType.Setter
        public Builder namespaceB(String namespaceB) {
            if (namespaceB == null) {
              throw new MissingRequiredPropertyException("GetDeployStagesDeployStageCollectionItemBlueGreenStrategy", "namespaceB");
            }
            this.namespaceB = namespaceB;
            return this;
        }
        @CustomType.Setter
        public Builder strategyType(String strategyType) {
            if (strategyType == null) {
              throw new MissingRequiredPropertyException("GetDeployStagesDeployStageCollectionItemBlueGreenStrategy", "strategyType");
            }
            this.strategyType = strategyType;
            return this;
        }
        public GetDeployStagesDeployStageCollectionItemBlueGreenStrategy build() {
            final var _resultValue = new GetDeployStagesDeployStageCollectionItemBlueGreenStrategy();
            _resultValue.ingressName = ingressName;
            _resultValue.namespaceA = namespaceA;
            _resultValue.namespaceB = namespaceB;
            _resultValue.strategyType = strategyType;
            return _resultValue;
        }
    }
}
