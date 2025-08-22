package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;

import java.util.ArrayList;


public class HostBlackListsValidatorThread extends Thread{

    private int start;
    private int end;
    private int ocurrences;
    private String ipaddress;
    private ArrayList<Integer> foundList = new ArrayList<>();

    public HostBlackListsValidatorThread(int start, int end, String ipadress){
        this.start = start;
        this.end = end;
        this.ipaddress = ipadress;
        this.ocurrences = 0;
    }

    @Override
    public void run() {
        HostBlacklistsDataSourceFacade skds = HostBlacklistsDataSourceFacade.getInstance();

        for (int i = start; i < end; i++) {

            if (skds.isInBlackListServer(i, ipaddress)) {
                foundList.add(i);
                ocurrences++;
            }
        }
    }

    public int getOcurrences(){
        return ocurrences;
    }

    public ArrayList<Integer> getFoundList(){
        return foundList;
    }
}
