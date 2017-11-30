

public class User implements java.io.Serializable {
	private String Name;
	private String ID;
	private String Password;
	private String Remark;

	public User(String Name, String ID, String Password, String Remark) {
		this.Name = Name;
		this.ID = ID;
		this.Password = Password;
		this.Remark = Remark;
	}

	public String getName() {
		return Name;
	}

	public void setName(String Name) {
		this.Name = Name;
	}

	public String getID() {
		return ID;
	}

	public void setID(String ID) {
		this.ID = ID;
	}

	public String getPassword() {
		return Password;
	}

	public void setPassword(String Password) {
		this.Password = Password;
	}

	public String getRemark() {
		return Remark;
	}

	public void setRemark(String Remark) {
		this.Remark = Remark;
	}

	@Override
	public String toString() {
		return String.format("User [%s %s %s %s]", this.Name, this.ID, this.Password, this.Remark);
	}
}