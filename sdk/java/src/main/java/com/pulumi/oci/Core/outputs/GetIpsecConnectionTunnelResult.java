// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Core.outputs.GetIpsecConnectionTunnelBgpSessionInfo;
import com.pulumi.oci.Core.outputs.GetIpsecConnectionTunnelDpdConfig;
import com.pulumi.oci.Core.outputs.GetIpsecConnectionTunnelEncryptionDomainConfig;
import com.pulumi.oci.Core.outputs.GetIpsecConnectionTunnelPhaseOneDetail;
import com.pulumi.oci.Core.outputs.GetIpsecConnectionTunnelPhaseTwoDetail;
import java.lang.Integer;
import java.lang.String;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetIpsecConnectionTunnelResult {
    private List<String> associatedVirtualCircuits;
    /**
     * @return Information needed to establish a BGP Session on an interface.
     * 
     */
    private List<GetIpsecConnectionTunnelBgpSessionInfo> bgpSessionInfos;
    /**
     * @return The OCID of the compartment containing the tunnel.
     * 
     */
    private String compartmentId;
    /**
     * @return The IP address of Cpe headend.  Example: `129.146.17.50`
     * 
     */
    private String cpeIp;
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    private String displayName;
    private List<GetIpsecConnectionTunnelDpdConfig> dpdConfigs;
    /**
     * @return Dead peer detection (DPD) mode set on the Oracle side of the connection.
     * 
     */
    private String dpdMode;
    /**
     * @return DPD timeout in seconds.
     * 
     */
    private Integer dpdTimeoutInSec;
    /**
     * @return Configuration information used by the encryption domain policy.
     * 
     */
    private List<GetIpsecConnectionTunnelEncryptionDomainConfig> encryptionDomainConfigs;
    /**
     * @return The tunnel&#39;s Oracle ID (OCID).
     * 
     */
    private String id;
    /**
     * @return Internet Key Exchange protocol version.
     * 
     */
    private String ikeVersion;
    private String ipsecId;
    /**
     * @return By default (the `AUTO` setting), IKE sends packets with a source and destination port set to 500, and when it detects that the port used to forward packets has changed (most likely because a NAT device is between the CPE device and the Oracle VPN headend) it will try to negotiate the use of NAT-T.
     * 
     */
    private String natTranslationEnabled;
    /**
     * @return Indicates whether Oracle can only respond to a request to start an IPSec tunnel from the CPE device, or both respond to and initiate requests.
     * 
     */
    private String oracleCanInitiate;
    /**
     * @return IPSec tunnel details specific to ISAKMP phase one.
     * 
     */
    private List<GetIpsecConnectionTunnelPhaseOneDetail> phaseOneDetails;
    /**
     * @return IPsec tunnel detail information specific to phase two.
     * 
     */
    private List<GetIpsecConnectionTunnelPhaseTwoDetail> phaseTwoDetails;
    /**
     * @return the routing strategy used for this tunnel, either static route or BGP dynamic routing
     * 
     */
    private String routing;
    private String sharedSecret;
    /**
     * @return The IPSec connection&#39;s tunnel&#39;s lifecycle state.
     * 
     */
    private String state;
    /**
     * @return The tunnel&#39;s current state.
     * 
     */
    private String status;
    /**
     * @return The date and time the IPSec connection tunnel was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeCreated;
    /**
     * @return When the status of the tunnel last changed, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    private String timeStatusUpdated;
    private String tunnelId;
    /**
     * @return The IP address of Oracle&#39;s VPN headend.  Example: `129.146.17.50`
     * 
     */
    private String vpnIp;

    private GetIpsecConnectionTunnelResult() {}
    public List<String> associatedVirtualCircuits() {
        return this.associatedVirtualCircuits;
    }
    /**
     * @return Information needed to establish a BGP Session on an interface.
     * 
     */
    public List<GetIpsecConnectionTunnelBgpSessionInfo> bgpSessionInfos() {
        return this.bgpSessionInfos;
    }
    /**
     * @return The OCID of the compartment containing the tunnel.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The IP address of Cpe headend.  Example: `129.146.17.50`
     * 
     */
    public String cpeIp() {
        return this.cpeIp;
    }
    /**
     * @return A user-friendly name. Does not have to be unique, and it&#39;s changeable. Avoid entering confidential information.
     * 
     */
    public String displayName() {
        return this.displayName;
    }
    public List<GetIpsecConnectionTunnelDpdConfig> dpdConfigs() {
        return this.dpdConfigs;
    }
    /**
     * @return Dead peer detection (DPD) mode set on the Oracle side of the connection.
     * 
     */
    public String dpdMode() {
        return this.dpdMode;
    }
    /**
     * @return DPD timeout in seconds.
     * 
     */
    public Integer dpdTimeoutInSec() {
        return this.dpdTimeoutInSec;
    }
    /**
     * @return Configuration information used by the encryption domain policy.
     * 
     */
    public List<GetIpsecConnectionTunnelEncryptionDomainConfig> encryptionDomainConfigs() {
        return this.encryptionDomainConfigs;
    }
    /**
     * @return The tunnel&#39;s Oracle ID (OCID).
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return Internet Key Exchange protocol version.
     * 
     */
    public String ikeVersion() {
        return this.ikeVersion;
    }
    public String ipsecId() {
        return this.ipsecId;
    }
    /**
     * @return By default (the `AUTO` setting), IKE sends packets with a source and destination port set to 500, and when it detects that the port used to forward packets has changed (most likely because a NAT device is between the CPE device and the Oracle VPN headend) it will try to negotiate the use of NAT-T.
     * 
     */
    public String natTranslationEnabled() {
        return this.natTranslationEnabled;
    }
    /**
     * @return Indicates whether Oracle can only respond to a request to start an IPSec tunnel from the CPE device, or both respond to and initiate requests.
     * 
     */
    public String oracleCanInitiate() {
        return this.oracleCanInitiate;
    }
    /**
     * @return IPSec tunnel details specific to ISAKMP phase one.
     * 
     */
    public List<GetIpsecConnectionTunnelPhaseOneDetail> phaseOneDetails() {
        return this.phaseOneDetails;
    }
    /**
     * @return IPsec tunnel detail information specific to phase two.
     * 
     */
    public List<GetIpsecConnectionTunnelPhaseTwoDetail> phaseTwoDetails() {
        return this.phaseTwoDetails;
    }
    /**
     * @return the routing strategy used for this tunnel, either static route or BGP dynamic routing
     * 
     */
    public String routing() {
        return this.routing;
    }
    public String sharedSecret() {
        return this.sharedSecret;
    }
    /**
     * @return The IPSec connection&#39;s tunnel&#39;s lifecycle state.
     * 
     */
    public String state() {
        return this.state;
    }
    /**
     * @return The tunnel&#39;s current state.
     * 
     */
    public String status() {
        return this.status;
    }
    /**
     * @return The date and time the IPSec connection tunnel was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeCreated() {
        return this.timeCreated;
    }
    /**
     * @return When the status of the tunnel last changed, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public String timeStatusUpdated() {
        return this.timeStatusUpdated;
    }
    public String tunnelId() {
        return this.tunnelId;
    }
    /**
     * @return The IP address of Oracle&#39;s VPN headend.  Example: `129.146.17.50`
     * 
     */
    public String vpnIp() {
        return this.vpnIp;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetIpsecConnectionTunnelResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<String> associatedVirtualCircuits;
        private List<GetIpsecConnectionTunnelBgpSessionInfo> bgpSessionInfos;
        private String compartmentId;
        private String cpeIp;
        private String displayName;
        private List<GetIpsecConnectionTunnelDpdConfig> dpdConfigs;
        private String dpdMode;
        private Integer dpdTimeoutInSec;
        private List<GetIpsecConnectionTunnelEncryptionDomainConfig> encryptionDomainConfigs;
        private String id;
        private String ikeVersion;
        private String ipsecId;
        private String natTranslationEnabled;
        private String oracleCanInitiate;
        private List<GetIpsecConnectionTunnelPhaseOneDetail> phaseOneDetails;
        private List<GetIpsecConnectionTunnelPhaseTwoDetail> phaseTwoDetails;
        private String routing;
        private String sharedSecret;
        private String state;
        private String status;
        private String timeCreated;
        private String timeStatusUpdated;
        private String tunnelId;
        private String vpnIp;
        public Builder() {}
        public Builder(GetIpsecConnectionTunnelResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.associatedVirtualCircuits = defaults.associatedVirtualCircuits;
    	      this.bgpSessionInfos = defaults.bgpSessionInfos;
    	      this.compartmentId = defaults.compartmentId;
    	      this.cpeIp = defaults.cpeIp;
    	      this.displayName = defaults.displayName;
    	      this.dpdConfigs = defaults.dpdConfigs;
    	      this.dpdMode = defaults.dpdMode;
    	      this.dpdTimeoutInSec = defaults.dpdTimeoutInSec;
    	      this.encryptionDomainConfigs = defaults.encryptionDomainConfigs;
    	      this.id = defaults.id;
    	      this.ikeVersion = defaults.ikeVersion;
    	      this.ipsecId = defaults.ipsecId;
    	      this.natTranslationEnabled = defaults.natTranslationEnabled;
    	      this.oracleCanInitiate = defaults.oracleCanInitiate;
    	      this.phaseOneDetails = defaults.phaseOneDetails;
    	      this.phaseTwoDetails = defaults.phaseTwoDetails;
    	      this.routing = defaults.routing;
    	      this.sharedSecret = defaults.sharedSecret;
    	      this.state = defaults.state;
    	      this.status = defaults.status;
    	      this.timeCreated = defaults.timeCreated;
    	      this.timeStatusUpdated = defaults.timeStatusUpdated;
    	      this.tunnelId = defaults.tunnelId;
    	      this.vpnIp = defaults.vpnIp;
        }

        @CustomType.Setter
        public Builder associatedVirtualCircuits(List<String> associatedVirtualCircuits) {
            if (associatedVirtualCircuits == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "associatedVirtualCircuits");
            }
            this.associatedVirtualCircuits = associatedVirtualCircuits;
            return this;
        }
        public Builder associatedVirtualCircuits(String... associatedVirtualCircuits) {
            return associatedVirtualCircuits(List.of(associatedVirtualCircuits));
        }
        @CustomType.Setter
        public Builder bgpSessionInfos(List<GetIpsecConnectionTunnelBgpSessionInfo> bgpSessionInfos) {
            if (bgpSessionInfos == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "bgpSessionInfos");
            }
            this.bgpSessionInfos = bgpSessionInfos;
            return this;
        }
        public Builder bgpSessionInfos(GetIpsecConnectionTunnelBgpSessionInfo... bgpSessionInfos) {
            return bgpSessionInfos(List.of(bgpSessionInfos));
        }
        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            if (compartmentId == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "compartmentId");
            }
            this.compartmentId = compartmentId;
            return this;
        }
        @CustomType.Setter
        public Builder cpeIp(String cpeIp) {
            if (cpeIp == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "cpeIp");
            }
            this.cpeIp = cpeIp;
            return this;
        }
        @CustomType.Setter
        public Builder displayName(String displayName) {
            if (displayName == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "displayName");
            }
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder dpdConfigs(List<GetIpsecConnectionTunnelDpdConfig> dpdConfigs) {
            if (dpdConfigs == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "dpdConfigs");
            }
            this.dpdConfigs = dpdConfigs;
            return this;
        }
        public Builder dpdConfigs(GetIpsecConnectionTunnelDpdConfig... dpdConfigs) {
            return dpdConfigs(List.of(dpdConfigs));
        }
        @CustomType.Setter
        public Builder dpdMode(String dpdMode) {
            if (dpdMode == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "dpdMode");
            }
            this.dpdMode = dpdMode;
            return this;
        }
        @CustomType.Setter
        public Builder dpdTimeoutInSec(Integer dpdTimeoutInSec) {
            if (dpdTimeoutInSec == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "dpdTimeoutInSec");
            }
            this.dpdTimeoutInSec = dpdTimeoutInSec;
            return this;
        }
        @CustomType.Setter
        public Builder encryptionDomainConfigs(List<GetIpsecConnectionTunnelEncryptionDomainConfig> encryptionDomainConfigs) {
            if (encryptionDomainConfigs == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "encryptionDomainConfigs");
            }
            this.encryptionDomainConfigs = encryptionDomainConfigs;
            return this;
        }
        public Builder encryptionDomainConfigs(GetIpsecConnectionTunnelEncryptionDomainConfig... encryptionDomainConfigs) {
            return encryptionDomainConfigs(List.of(encryptionDomainConfigs));
        }
        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder ikeVersion(String ikeVersion) {
            if (ikeVersion == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "ikeVersion");
            }
            this.ikeVersion = ikeVersion;
            return this;
        }
        @CustomType.Setter
        public Builder ipsecId(String ipsecId) {
            if (ipsecId == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "ipsecId");
            }
            this.ipsecId = ipsecId;
            return this;
        }
        @CustomType.Setter
        public Builder natTranslationEnabled(String natTranslationEnabled) {
            if (natTranslationEnabled == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "natTranslationEnabled");
            }
            this.natTranslationEnabled = natTranslationEnabled;
            return this;
        }
        @CustomType.Setter
        public Builder oracleCanInitiate(String oracleCanInitiate) {
            if (oracleCanInitiate == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "oracleCanInitiate");
            }
            this.oracleCanInitiate = oracleCanInitiate;
            return this;
        }
        @CustomType.Setter
        public Builder phaseOneDetails(List<GetIpsecConnectionTunnelPhaseOneDetail> phaseOneDetails) {
            if (phaseOneDetails == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "phaseOneDetails");
            }
            this.phaseOneDetails = phaseOneDetails;
            return this;
        }
        public Builder phaseOneDetails(GetIpsecConnectionTunnelPhaseOneDetail... phaseOneDetails) {
            return phaseOneDetails(List.of(phaseOneDetails));
        }
        @CustomType.Setter
        public Builder phaseTwoDetails(List<GetIpsecConnectionTunnelPhaseTwoDetail> phaseTwoDetails) {
            if (phaseTwoDetails == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "phaseTwoDetails");
            }
            this.phaseTwoDetails = phaseTwoDetails;
            return this;
        }
        public Builder phaseTwoDetails(GetIpsecConnectionTunnelPhaseTwoDetail... phaseTwoDetails) {
            return phaseTwoDetails(List.of(phaseTwoDetails));
        }
        @CustomType.Setter
        public Builder routing(String routing) {
            if (routing == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "routing");
            }
            this.routing = routing;
            return this;
        }
        @CustomType.Setter
        public Builder sharedSecret(String sharedSecret) {
            if (sharedSecret == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "sharedSecret");
            }
            this.sharedSecret = sharedSecret;
            return this;
        }
        @CustomType.Setter
        public Builder state(String state) {
            if (state == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "state");
            }
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder status(String status) {
            if (status == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "status");
            }
            this.status = status;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreated(String timeCreated) {
            if (timeCreated == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "timeCreated");
            }
            this.timeCreated = timeCreated;
            return this;
        }
        @CustomType.Setter
        public Builder timeStatusUpdated(String timeStatusUpdated) {
            if (timeStatusUpdated == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "timeStatusUpdated");
            }
            this.timeStatusUpdated = timeStatusUpdated;
            return this;
        }
        @CustomType.Setter
        public Builder tunnelId(String tunnelId) {
            if (tunnelId == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "tunnelId");
            }
            this.tunnelId = tunnelId;
            return this;
        }
        @CustomType.Setter
        public Builder vpnIp(String vpnIp) {
            if (vpnIp == null) {
              throw new MissingRequiredPropertyException("GetIpsecConnectionTunnelResult", "vpnIp");
            }
            this.vpnIp = vpnIp;
            return this;
        }
        public GetIpsecConnectionTunnelResult build() {
            final var _resultValue = new GetIpsecConnectionTunnelResult();
            _resultValue.associatedVirtualCircuits = associatedVirtualCircuits;
            _resultValue.bgpSessionInfos = bgpSessionInfos;
            _resultValue.compartmentId = compartmentId;
            _resultValue.cpeIp = cpeIp;
            _resultValue.displayName = displayName;
            _resultValue.dpdConfigs = dpdConfigs;
            _resultValue.dpdMode = dpdMode;
            _resultValue.dpdTimeoutInSec = dpdTimeoutInSec;
            _resultValue.encryptionDomainConfigs = encryptionDomainConfigs;
            _resultValue.id = id;
            _resultValue.ikeVersion = ikeVersion;
            _resultValue.ipsecId = ipsecId;
            _resultValue.natTranslationEnabled = natTranslationEnabled;
            _resultValue.oracleCanInitiate = oracleCanInitiate;
            _resultValue.phaseOneDetails = phaseOneDetails;
            _resultValue.phaseTwoDetails = phaseTwoDetails;
            _resultValue.routing = routing;
            _resultValue.sharedSecret = sharedSecret;
            _resultValue.state = state;
            _resultValue.status = status;
            _resultValue.timeCreated = timeCreated;
            _resultValue.timeStatusUpdated = timeStatusUpdated;
            _resultValue.tunnelId = tunnelId;
            _resultValue.vpnIp = vpnIp;
            return _resultValue;
        }
    }
}
